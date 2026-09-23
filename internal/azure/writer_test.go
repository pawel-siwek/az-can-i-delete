package azure_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

const accountPath = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Storage/storageAccounts/st1"

// jwtCredential hands out an unsigned token with the claims a test chooses.
// ARM is what verifies a token; the writer only reads two ids out of it.
type jwtCredential struct{ claims map[string]string }

func (c jwtCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	payload, _ := json.Marshal(c.claims)
	token := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	return azcore.AccessToken{Token: token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeClock advances only when the code under test sleeps.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fakeClock) clock() collect.Clock {
	return collect.Clock{
		Now: func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at },
		Sleep: func(_ context.Context, d time.Duration) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.at = c.at.Add(d)
			return nil
		},
	}
}

type writeServer struct {
	mu       sync.Mutex
	requests []request
	handler  func(w http.ResponseWriter, r *http.Request, url string)
	url      string
}

func newWriter(t *testing.T, claims map[string]string, handler func(w http.ResponseWriter, r *http.Request, url string)) (cordon.Writer, *writeServer) {
	t.Helper()
	s := &writeServer{handler: handler}
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded := request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) == nil {
			recorded.Body = body
		}
		s.mu.Lock()
		s.requests = append(s.requests, recorded)
		s.mu.Unlock()
		s.handler(w, r, s.url)
	}))
	t.Cleanup(httpServer.Close)
	s.url = httpServer.URL
	client, err := azure.New(azure.Options{Endpoint: httpServer.URL, Credential: jwtCredential{claims}, Transport: httpServer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{at: time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)}
	return client.Writer(clock.clock()), s
}

func TestPatchFollowsTheOperationToItsEnd(t *testing.T) {
	polls := 0
	writer, s := newWriter(t, nil, func(w http.ResponseWriter, r *http.Request, url string) {
		switch {
		case r.Method == http.MethodPatch:
			w.Header().Set("Azure-AsyncOperation", url+"/operations/op1?api-version=x")
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/operations/op1"):
			polls++
			status := "InProgress"
			if polls == 3 {
				status = "Succeeded"
			}
			_, _ = w.Write([]byte(`{"status":"` + status + `"}`))
		}
	})
	err := writer.Patch(context.Background(), accountPath, storageVersion(t), map[string]any{"properties": map[string]any{"publicNetworkAccess": "Disabled"}})
	if err != nil || polls != 3 {
		t.Fatalf("err %v after %d polls", err, polls)
	}
	first := s.requests[0]
	if first.Query["api-version"][0] != storageVersion(t) || first.Body["properties"].(map[string]any)["publicNetworkAccess"] != "Disabled" {
		t.Fatalf("request = %+v", first)
	}
}

func TestAnOperationThatNeverEndsIsStillRunningNotDone(t *testing.T) {
	writer, _ := newWriter(t, nil, func(w http.ResponseWriter, r *http.Request, url string) {
		if r.Method == http.MethodPost {
			w.Header().Set("Location", url+"/operationResults/op2")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	err := writer.Action(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app1", "stop", siteVersion(t))
	if !errors.Is(err, cordon.ErrStillRunning) {
		t.Fatalf("err = %v", err)
	}
}

func TestAFailedOperationIsAFailure(t *testing.T) {
	writer, _ := newWriter(t, nil, func(w http.ResponseWriter, r *http.Request, url string) {
		if r.Method == http.MethodPatch {
			w.Header().Set("Azure-AsyncOperation", url+"/operations/op3")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = w.Write([]byte(`{"status":"Failed"}`))
	})
	err := writer.Patch(context.Background(), accountPath, storageVersion(t), map[string]any{})
	var failure *collect.Failure
	if !errors.As(err, &failure) || failure.ErrorCode != "OperationFailed" {
		t.Fatalf("err = %v", err)
	}
}

// The poller address is Azure's text. Following it to another host would hand
// that host the bearer token.
func TestAPollerOffTheManagementEndpointIsNotFollowed(t *testing.T) {
	writer, s := newWriter(t, nil, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Azure-AsyncOperation", "https://attacker.example/operations/1")
		w.WriteHeader(http.StatusAccepted)
	})
	err := writer.Patch(context.Background(), accountPath, storageVersion(t), map[string]any{})
	var failure *collect.Failure
	if !errors.As(err, &failure) || failure.ErrorCode != "UntrustedPoller" || len(s.requests) != 1 {
		t.Fatalf("err %v requests %d", err, len(s.requests))
	}
}

func TestTagsGoThroughTheTagsResource(t *testing.T) {
	writer, s := newWriter(t, nil, func(w http.ResponseWriter, _ *http.Request, _ string) { _, _ = w.Write([]byte(`{}`)) })
	if err := writer.Tags(context.Background(), accountPath, cordon.TagMerge, map[string]string{"azcid": "v=1"}); err != nil {
		t.Fatal(err)
	}
	got := s.requests[0]
	if got.Method != http.MethodPatch || got.Path != accountPath+"/providers/Microsoft.Resources/tags/default" ||
		got.Query["api-version"][0] != rules.MustOperation("tags") || got.Body["operation"] != "Merge" ||
		got.Body["properties"].(map[string]any)["tags"].(map[string]any)["azcid"] != "v=1" {
		t.Fatalf("request = %+v", got)
	}
}

func TestCheckPolicyReadsDenyAndModifyOnTheFlippedField(t *testing.T) {
	cases := map[string]struct {
		answer     string
		restricted bool
		effects    string
	}{
		"nothing":             {`{"fieldRestrictions":[],"contentEvaluationResult":{"policyEvaluations":[]}}`, false, ""},
		"deny on the field":   {`{"fieldRestrictions":[{"field":"Microsoft.Storage/storageAccounts/publicNetworkAccess","restrictions":[{"result":"Deny"}]}]}`, true, "Deny"},
		"modify on the field": {`{"fieldRestrictions":[{"field":"microsoft.storage/storageaccounts/publicnetworkaccess","restrictions":[{"result":"Required"}]}]}`, true, "Modify"},
		"another field":       {`{"fieldRestrictions":[{"field":"location","restrictions":[{"result":"Deny"}]}]}`, false, ""},
		"audit only":          {`{"contentEvaluationResult":{"policyEvaluations":[{"evaluationResult":"NonCompliant","effectDetails":{"policyEffect":"Audit"}}]}}`, false, ""},
		"denied content":      {`{"contentEvaluationResult":{"policyEvaluations":[{"evaluationResult":"NonCompliant","effectDetails":{"policyEffect":"Deny"}}]}}`, true, "Deny"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			writer, s := newWriter(t, nil, func(w http.ResponseWriter, _ *http.Request, _ string) { _, _ = w.Write([]byte(tc.answer)) })
			result, err := writer.CheckPolicy(context.Background(), cordon.PolicyCheck{
				Scope: groupID, APIVersion: storageVersion(t), Field: "Microsoft.Storage/storageAccounts/publicNetworkAccess",
				Content: map[string]any{"type": "Microsoft.Storage/storageAccounts", "properties": map[string]any{"publicNetworkAccess": "Enabled"}},
			})
			if err != nil || result.Restricted != tc.restricted || strings.Join(result.Effects, ",") != tc.effects {
				t.Fatalf("result %+v err %v", result, err)
			}
			got := s.requests[0]
			if got.Method != http.MethodPost || got.Path != groupID+"/providers/Microsoft.PolicyInsights/checkPolicyRestrictions" ||
				got.Query["api-version"][0] != rules.MustOperation("policyInsights") {
				t.Fatalf("request = %+v", got)
			}
		})
	}
}

func TestThePrincipalComesFromTheTokenClaims(t *testing.T) {
	writer, _ := newWriter(t, map[string]string{"oid": "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9", "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"}, nil)
	principal, err := writer.Principal(context.Background())
	if err != nil || principal.ObjectID != "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9" || principal.AppID != "04b07795-8ddb-461a-bbee-02f9e1bf7b46" {
		t.Fatalf("principal %+v err %v", principal, err)
	}
	writer, _ = newWriter(t, map[string]string{"sub": "nobody"}, nil)
	if _, err := writer.Principal(context.Background()); err == nil {
		t.Fatal("a token without an object id was accepted")
	}
}

// The versions come from the rule table, like every call site's (ADR-0008).
func storageVersion(t *testing.T) string {
	t.Helper()
	version, err := rules.APIVersion("Microsoft.Storage/storageAccounts")
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func siteVersion(t *testing.T) string {
	t.Helper()
	version, err := rules.APIVersion("Microsoft.Web/sites")
	if err != nil {
		t.Fatal(err)
	}
	return version
}
