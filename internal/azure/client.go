// Package azure implements the collect boundaries against Azure Resource
// Manager. It issues plain REST calls through the azcore pipeline rather than
// a typed SDK client per resource provider: every api-version is pinned in
// internal/rules, so the request states the version it was answered under and
// a pin can be corrected without touching a collector.
//
// The package never acquires an account key, a shared access signature or any
// other secret, and it never retries on its own: retries, throttling and the
// run budget belong to internal/collect, which also turns every failure here
// into an unknown rather than into silence.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
)

const (
	module          = "az-can-i-delete"
	defaultEndpoint = "https://management.azure.com"
	managementScope = "https://management.azure.com/.default"
	// MaxPages bounds every paged list. A listing that is still not finished
	// is reported as truncated, never as a complete answer.
	MaxPages = 20
)

// Options configures the client. Everything has a public-cloud default;
// Endpoint and Transport exist so the adapters can be tested without a tenant.
type Options struct {
	Endpoint    string
	Credential  azcore.TokenCredential
	Transport   policy.Transporter
	Scope       string
	ToolVersion string
}

// Client is the shared transport for every Azure boundary.
type Client struct {
	pipeline   runtime.Pipeline
	endpoint   string
	credential azcore.TokenCredential
	scope      string
}

// Credential is the chain REQUIREMENTS section 7 pins: DefaultAzureCredential
// first, which covers environment, workload identity, managed identity, the
// Azure CLI and Cloud Shell's MSI_ENDPOINT, then the Azure CLI on its own when
// the default chain cannot even be constructed. No account keys, no shared
// access signatures and no assumption that a managed identity exists.
func Credential() (azcore.TokenCredential, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err == nil {
		return credential, nil
	}
	cli, cliErr := azidentity.NewAzureCLICredential(nil)
	if cliErr != nil {
		return nil, fmt.Errorf("no usable Azure credential: %w", errors.Join(err, cliErr))
	}
	return cli, nil
}

// New builds the shared client. Pipeline retries are disabled on purpose: the
// collection layer owns retries so that a retry, its Retry-After wait and the
// run budget are all accounted for in one place.
func New(opts Options) (*Client, error) {
	if opts.Credential == nil {
		credential, err := Credential()
		if err != nil {
			return nil, err
		}
		opts.Credential = credential
	}
	if opts.Endpoint == "" {
		opts.Endpoint = defaultEndpoint
	}
	if opts.Scope == "" {
		opts.Scope = managementScope
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}
	authPolicy := runtime.NewBearerTokenPolicy(opts.Credential, []string{opts.Scope}, nil)
	pipeline := runtime.NewPipeline(module, opts.ToolVersion,
		runtime.PipelineOptions{PerRetry: []policy.Policy{authPolicy}},
		&policy.ClientOptions{
			Transport: opts.Transport,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		})
	return &Client{pipeline: pipeline, endpoint: strings.TrimSuffix(opts.Endpoint, "/"),
		credential: opts.Credential, scope: opts.Scope}, nil
}

// ARM exposes the control-plane boundary.
func (c *Client) ARM() collect.ARMClient { return &armClient{client: c} }

// Graph exposes the Resource Graph boundary.
func (c *Client) Graph() collect.GraphClient { return &graphClient{client: c} }

// Metrics exposes the Azure Monitor metrics boundary.
func (c *Client) Metrics() collect.MetricsClient { return &metricsClient{client: c} }

// ActivityLog exposes the Activity Log boundary.
func (c *Client) ActivityLog() collect.ActivityLogClient { return &activityLogClient{client: c} }

// get issues one GET and decodes the body into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.do(ctx, http.MethodGet, c.url(path, query), nil, out)
}

// post issues one POST with a JSON body.
func (c *Client) post(ctx context.Context, path string, query url.Values, body, out any) error {
	return c.do(ctx, http.MethodPost, c.url(path, query), body, out)
}

func (c *Client) url(path string, query url.Values) string {
	address := c.endpoint + "/" + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		address += "?" + query.Encode()
	}
	return address
}

func (c *Client) do(ctx context.Context, method, address string, body, out any) error {
	request, err := runtime.NewRequest(ctx, method, address)
	if err != nil {
		return &collect.Failure{Message: "the request could not be built", Err: err}
	}
	if body != nil {
		if err := runtime.MarshalAsJSON(request, body); err != nil {
			return &collect.Failure{Message: "the request body could not be encoded", Err: err}
		}
	}
	response, err := c.pipeline.Do(request)
	if err != nil {
		return &collect.Failure{Message: "the request failed", Err: err}
	}
	defer response.Body.Close() //nolint:errcheck // the response body is drained below
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return failure(response)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return &collect.Failure{StatusCode: response.StatusCode, Message: "the response could not be read", Err: err}
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return &collect.Failure{StatusCode: response.StatusCode, Message: "the response could not be decoded", Err: err}
	}
	return nil
}

// failure turns an Azure error response into the classified failure the
// collection layer understands. The service message is kept for diagnostics
// only; the output boundary never publishes it.
func failure(response *http.Response) error {
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(payload, &body)
	message := body.Error.Message
	if message == "" {
		message = strings.TrimSpace(string(bytes.TrimSpace(payload)))
	}
	return &collect.Failure{
		StatusCode: response.StatusCode,
		ErrorCode:  body.Error.Code,
		Message:    message,
		RetryAfter: retryAfter(response.Header),
	}
}

// retryAfter reads the server's wait hint in either of its documented forms.
func retryAfter(header http.Header) time.Duration {
	for _, name := range []string{"Retry-After", "x-ms-ratelimit-remaining-retry-after"} {
		value := header.Get(name)
		if value == "" {
			continue
		}
		if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
			return time.Duration(seconds) * time.Second
		}
		if when, err := http.ParseTime(value); err == nil {
			if wait := time.Until(when); wait > 0 {
				return wait
			}
		}
	}
	return 0
}

// page is the shape every ARM list answers with.
type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

// list follows nextLink up to MaxPages. It reports whether the listing was cut
// short so the caller can degrade to unknown(partial) instead of claiming that
// nothing more exists.
func list[T any](ctx context.Context, c *Client, path string, query url.Values) (items []T, complete bool, err error) {
	address := c.url(path, query)
	for pages := 0; pages < MaxPages; pages++ {
		var current page[T]
		if err := c.do(ctx, http.MethodGet, address, nil, &current); err != nil {
			return nil, false, err
		}
		items = append(items, current.Value...)
		if current.NextLink == "" {
			return items, true, nil
		}
		address = current.NextLink
	}
	return items, false, nil
}

// Recorded builds a client that reads a recording instead of Azure.
//
// It lives here because the SDK types do: ADR-0010 keeps the pipeline, the
// transporter and the credential inside this package, so internal/replay can
// be a plain http.RoundTripper that knows nothing about any of them.
//
// The credential is a placeholder rather than a real one. A recorded run must
// work on a machine that has never signed in — otherwise a demonstration fails
// for a reason that has nothing to do with what it is demonstrating — and
// there is nothing on the other end to authenticate to.
func Recorded(transport http.RoundTripper, toolVersion string) (*Client, error) {
	if transport == nil {
		return nil, errors.New("a recording needs a transport to read it")
	}
	return New(Options{
		ToolVersion: toolVersion,
		Credential:  recordedCredential{},
		Transport:   roundTripper{transport},
	})
}

// Transport adapts a standard transport to the SDK's, so a caller outside this
// package can supply one without naming an SDK type.
func Transport(inner http.RoundTripper) policy.Transporter { return roundTripper{inner} }

// RecordedCredential is the placeholder a replay signs with. Exported so a
// recording can be made against a test endpoint, which needs no identity
// either.
func RecordedCredential() azcore.TokenCredential { return recordedCredential{} }

// roundTripper adapts a standard transport to the SDK's.
type roundTripper struct{ inner http.RoundTripper }

func (r roundTripper) Do(request *http.Request) (*http.Response, error) {
	return r.inner.RoundTrip(request)
}

type recordedCredential struct{}

func (recordedCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "replay", ExpiresOn: time.Now().Add(time.Hour)}, nil
}
