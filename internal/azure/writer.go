package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

// The long-running operation budget of SPEC appendix E section 6.3 step 4.
const (
	PollInterval = 2 * time.Second
	PollDeadline = 5 * time.Minute
)

// writer is the cordon boundary. It is built only by the cordon commands;
// the assessment clients above expose no write of any kind (ADR-0005).
type writer struct {
	client *Client
	clock  collect.Clock
}

// Writer exposes the cordon's write boundary. Nothing on the check path
// calls it.
func (c *Client) Writer(clock collect.Clock) cordon.Writer {
	return &writer{client: c, clock: clock}
}

// Principal reads the caller's object id and application id from the ARM
// token's own claims. The token is not verified here — ARM verifies it on
// every call — and nothing but the two ids is kept.
func (w *writer) Principal(ctx context.Context) (cordon.Principal, error) {
	token, err := w.client.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{w.client.scope}})
	if err != nil {
		return cordon.Principal{}, &collect.Failure{Message: "a token could not be acquired", Err: err}
	}
	parts := strings.Split(token.Token, ".")
	if len(parts) != 3 {
		return cordon.Principal{}, &collect.Failure{ErrorCode: "InvalidToken", Message: "the token is not a JWT"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cordon.Principal{}, &collect.Failure{ErrorCode: "InvalidToken", Message: "the token's claims could not be decoded"}
	}
	var claims struct {
		OID   string `json:"oid"`
		AppID string `json:"appid"`
		AZP   string `json:"azp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return cordon.Principal{}, &collect.Failure{ErrorCode: "InvalidToken", Message: "the token's claims could not be decoded"}
	}
	oid := strings.ToLower(claims.OID)
	if !guid.MatchString(oid) {
		return cordon.Principal{}, &collect.Failure{ErrorCode: "InvalidToken", Message: "the token carries no object id"}
	}
	app := claims.AppID
	if app == "" {
		app = claims.AZP
	}
	return cordon.Principal{ObjectID: oid, AppID: appID(app)}, nil
}

// Patch sends a merge body to a resource and waits for it to finish.
func (w *writer) Patch(ctx context.Context, resourceID, apiVersion string, body map[string]any) error {
	return w.send(ctx, http.MethodPatch, resourceID, url.Values{"api-version": {apiVersion}}, body)
}

// Action POSTs to resourceID/action and waits for it to finish.
func (w *writer) Action(ctx context.Context, resourceID, action, apiVersion string) error {
	return w.send(ctx, http.MethodPost, strings.TrimSuffix(resourceID, "/")+"/"+action, url.Values{"api-version": {apiVersion}}, nil)
}

// Tags merges or deletes tags through the tags resource, which leaves every
// other tag where it was.
func (w *writer) Tags(ctx context.Context, resourceID string, operation cordon.TagOperation, tags map[string]string) error {
	return w.send(ctx, http.MethodPatch, strings.TrimSuffix(resourceID, "/")+"/providers/Microsoft.Resources/tags/default",
		url.Values{"api-version": {rules.MustOperation("tags")}},
		map[string]any{"operation": string(operation), "properties": map[string]any{"tags": tags}})
}

// policyAnswer is the part of a checkPolicyRestrictions answer a cordon reads.
type policyAnswer struct {
	FieldRestrictions []struct {
		Field        string `json:"field"`
		Restrictions []struct {
			Result string `json:"result"`
		} `json:"restrictions"`
	} `json:"fieldRestrictions"`
	ContentEvaluationResult struct {
		PolicyEvaluations []struct {
			EvaluationResult string `json:"evaluationResult"`
			EffectDetails    struct {
				PolicyEffect string `json:"policyEffect"`
			} `json:"effectDetails"`
		} `json:"policyEvaluations"`
	} `json:"contentEvaluationResult"`
}

// CheckPolicy asks what Azure Policy would do to a body at a scope. A field
// restriction that denies, requires or removes the flipped field, or a
// non-compliant Deny or Modify on the content, is a restriction.
func (w *writer) CheckPolicy(ctx context.Context, check cordon.PolicyCheck) (cordon.PolicyResult, error) {
	request := map[string]any{
		"resourceDetails": map[string]any{
			"resourceContent": check.Content, "apiVersion": check.APIVersion, "scope": check.Scope,
		},
		"includeAuditEffect": false,
	}
	if check.Field != "" {
		request["pendingFields"] = []any{map[string]any{"field": check.Field}}
	}
	var answer policyAnswer
	path := strings.TrimSuffix(check.Scope, "/") + "/providers/Microsoft.PolicyInsights/checkPolicyRestrictions"
	if err := w.client.post(ctx, path, url.Values{"api-version": {rules.MustOperation("policyInsights")}}, request, &answer); err != nil {
		return cordon.PolicyResult{}, err
	}
	var result cordon.PolicyResult
	seen := map[string]bool{}
	add := func(effect string) {
		result.Restricted = true
		if !seen[effect] {
			seen[effect] = true
			result.Effects = append(result.Effects, effect)
		}
	}
	for _, field := range answer.FieldRestrictions {
		if check.Field == "" || !strings.EqualFold(field.Field, check.Field) {
			continue
		}
		for _, restriction := range field.Restrictions {
			switch strings.ToLower(restriction.Result) {
			case "deny":
				add("Deny")
			case "required", "removed":
				add("Modify")
			}
		}
	}
	for _, evaluation := range answer.ContentEvaluationResult.PolicyEvaluations {
		if !strings.EqualFold(evaluation.EvaluationResult, "NonCompliant") {
			continue
		}
		switch effect := strings.ToLower(evaluation.EffectDetails.PolicyEffect); effect {
		case "deny":
			add("Deny")
		case "modify":
			add("Modify")
		}
	}
	return result, nil
}

// send issues one write and, when Azure answers that it has only started,
// polls the operation to a terminal state.
func (w *writer) send(ctx context.Context, method, path string, query url.Values, body any) error {
	request, err := runtime.NewRequest(ctx, method, w.client.url(path, query))
	if err != nil {
		return &collect.Failure{Message: "the request could not be built", Err: err}
	}
	if body != nil {
		if err := runtime.MarshalAsJSON(request, body); err != nil {
			return &collect.Failure{Message: "the request body could not be encoded", Err: err}
		}
	}
	response, err := w.client.pipeline.Do(request)
	if err != nil {
		return &collect.Failure{Message: "the request failed", Err: err}
	}
	defer response.Body.Close() //nolint:errcheck // drained below
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return failure(response)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusCreated {
		return nil
	}
	return w.poll(ctx, response.Header)
}

// poll follows Azure-AsyncOperation, or Location when that is all there is.
// It follows only addresses on the management endpoint: a poller URL is
// Azure's text, and the bearer token must not go anywhere else.
func (w *writer) poll(ctx context.Context, header http.Header) error {
	address, async := header.Get("Azure-AsyncOperation"), true
	if address == "" {
		address, async = header.Get("Location"), false
	}
	if address == "" {
		return nil
	}
	if !w.sameEndpoint(address) {
		return &collect.Failure{ErrorCode: "UntrustedPoller", Message: "the operation status address is not on the management endpoint"}
	}
	deadline := w.clock.Now().Add(PollDeadline)
	for {
		if err := w.clock.Sleep(ctx, PollInterval); err != nil {
			return err
		}
		if w.clock.Now().After(deadline) {
			return cordon.ErrStillRunning
		}
		done, err := w.pollOnce(ctx, address, async)
		if err != nil || done {
			return err
		}
	}
}

func (w *writer) pollOnce(ctx context.Context, address string, async bool) (bool, error) {
	request, err := runtime.NewRequest(ctx, http.MethodGet, address)
	if err != nil {
		return false, &collect.Failure{Message: "the request could not be built", Err: err}
	}
	response, err := w.client.pipeline.Do(request)
	if err != nil {
		return false, &collect.Failure{Message: "the request failed", Err: err}
	}
	defer response.Body.Close() //nolint:errcheck // drained below
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return false, failure(response)
	}
	if !async {
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode != http.StatusAccepted, nil
	}
	var status struct {
		Status string `json:"status"`
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || json.Unmarshal(payload, &status) != nil {
		return false, &collect.Failure{StatusCode: response.StatusCode, Message: "the operation status could not be read"}
	}
	switch strings.ToLower(status.Status) {
	case "succeeded":
		return true, nil
	case "failed", "canceled", "cancelled":
		return false, &collect.Failure{StatusCode: http.StatusConflict, ErrorCode: "OperationFailed", Message: "the operation did not succeed"}
	}
	return false, nil
}

func (w *writer) sameEndpoint(address string) bool {
	poller, err := url.Parse(address)
	if err != nil {
		return false
	}
	endpoint, err := url.Parse(w.client.endpoint)
	if err != nil {
		return false
	}
	return strings.EqualFold(poller.Scheme, endpoint.Scheme) && strings.EqualFold(poller.Host, endpoint.Host)
}
