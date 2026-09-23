package azure

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

// The storage data plane, read with the caller's own token and nothing else.
//
// There is no code path here that acquires an account key, calls listKeys or
// falls back to a SAS, and there is no field to put one in. A caller who
// cannot read a container gets the 403 as unknown(permission); that is the
// whole answer, and it is the honest one.

const (
	// storageScope is the OAuth scope for the storage data plane. It is not
	// the management scope: a token for ARM does not open a container, which
	// is exactly why this is opt-in.
	storageScope = "https://storage.azure.com/.default"
	// blobSuffix is the public-cloud blob endpoint suffix.
	blobSuffix = "blob.core.windows.net"
)

// partitions are the levels a logging producer writes, deepest last. The walk
// descends them one level at a time, which is what keeps it to a handful of
// calls instead of a listing of every blob.
var partitions = []string{"y=", "m=", "d=", "h="}

// DataPlaneOptions configures the data-plane client. Endpoint exists so the
// walk can be tested against a local server; there is deliberately no option
// that could carry a key or a signature.
type DataPlaneOptions struct {
	Endpoint    string
	Credential  azcore.TokenCredential
	Transport   policy.Transporter
	ToolVersion string
}

// DataPlane builds the opt-in data-plane boundary. It is constructed only when
// the caller passed --data-plane, so the token for the storage scope is never
// requested on an ordinary run.
func DataPlane(opts DataPlaneOptions) (collect.DataPlaneClient, error) {
	credential := opts.Credential
	if credential == nil {
		found, err := Credential()
		if err != nil {
			return nil, err
		}
		credential = found
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}
	authPolicy := runtime.NewBearerTokenPolicy(credential, []string{storageScope}, nil)
	pipeline := runtime.NewPipeline(module, opts.ToolVersion,
		runtime.PipelineOptions{PerRetry: []policy.Policy{authPolicy}},
		&policy.ClientOptions{
			Transport: opts.Transport,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		})
	return &dataPlaneClient{pipeline: pipeline, endpoint: strings.TrimSuffix(opts.Endpoint, "/")}, nil
}

type dataPlaneClient struct {
	pipeline runtime.Pipeline
	endpoint string
}

// account returns the blob endpoint for a storage account's ARM id.
func (c *dataPlaneClient) account(accountID string) (string, error) {
	if c.endpoint != "" {
		return c.endpoint, nil
	}
	target, err := armid.Parse(accountID)
	if err != nil {
		return "", &collect.Failure{Message: "the account id could not be parsed", Err: err}
	}
	return "https://" + target.Name + "." + blobSuffix, nil
}

// Containers lists the account's containers through the data plane. The ARM
// listing is the one the analyzer uses; this exists for a caller that has data
// access but not the control-plane listing.
func (c *dataPlaneClient) Containers(ctx context.Context, accountID string, limit int) ([]collect.Container, error) {
	base, err := c.account(accountID)
	if err != nil {
		return nil, err
	}
	query := url.Values{"comp": {"list"}}
	if limit > 0 {
		query.Set("maxresults", fmt.Sprint(limit))
	}
	var result containerEnumeration
	if err := c.get(ctx, base+"/?"+query.Encode(), &result); err != nil {
		return nil, err
	}
	containers := make([]collect.Container, 0, len(result.Containers.Items))
	for _, item := range result.Containers.Items {
		containers = append(containers, collect.Container{Name: item.Name, LeaseState: item.Properties.LeaseState})
	}
	return containers, nil
}

// PrefixWalk descends the y=/m=/d=/h= partitions of one container, taking the
// latest partition at each level, and reports the most recent write it reached.
//
// It stops at the budget rather than at an answer: an exhausted budget is
// reported as an incomplete walk, which the analyzer turns into unknown. A
// walk that guessed at what it had not read would be worse than no walk.
func (c *dataPlaneClient) PrefixWalk(ctx context.Context, accountID, container string, budget collect.PrefixBudget) (collect.Prefix, error) {
	base, err := c.account(accountID)
	if err != nil {
		return collect.Prefix{}, err
	}
	deadline := time.Now().Add(budget.MaxTime)
	if budget.MaxTime <= 0 {
		deadline = time.Now().Add(maxWalkTime)
	}
	calls := budget.MaxCalls
	if calls <= 0 {
		calls = maxWalkCalls
	}

	prefix := ""
	var newest time.Time
	// One listing per partition level, and one more for the deepest level
	// reached: the blobs that carry the dates live under the last prefix, so a
	// walk that stopped at the descent would never read a write.
	for level := 0; level <= len(partitions); level++ {
		if calls <= 0 || time.Now().After(deadline) {
			return collect.Prefix{Path: prefix, LastWrite: newest, Complete: false}, nil
		}
		calls--

		listing, err := c.list(ctx, base, container, prefix)
		if err != nil {
			return collect.Prefix{}, err
		}
		for _, blob := range listing.Blobs.Items {
			if written := blob.Properties.LastModified.Time(); written.After(newest) {
				newest = written
			}
		}
		if level == len(partitions) {
			break
		}
		next := latest(listing.Blobs.Prefixes, partitions[level])
		if next == "" {
			// No deeper partition: this is as far as the layout goes, and the
			// walk finished rather than ran out.
			return collect.Prefix{Path: prefix, LastWrite: newest, Complete: true}, nil
		}
		prefix = next
	}
	return collect.Prefix{Path: prefix, LastWrite: newest, Complete: true}, nil
}

// The defaults used when a caller passes no budget. They are the section 3.2
// bounds, so a missing budget is still a bounded walk.
const (
	maxWalkCalls = 12
	maxWalkTime  = 3 * time.Second
)

// latest picks the highest-sorting prefix at this level, which for the
// zero-padded y=/m=/d=/h= layout is the most recent one.
func latest(prefixes []blobPrefix, level string) string {
	best := ""
	for _, candidate := range prefixes {
		name := candidate.Name
		trimmed := strings.TrimSuffix(name, "/")
		last := trimmed[strings.LastIndex(trimmed, "/")+1:]
		if !strings.HasPrefix(last, level) {
			continue
		}
		if name > best {
			best = name
		}
	}
	return best
}

// list issues one delimited listing, which returns the blobs directly under a
// prefix and the prefixes one level below it.
func (c *dataPlaneClient) list(ctx context.Context, base, container, prefix string) (*blobEnumeration, error) {
	query := url.Values{
		"restype":   {"container"},
		"comp":      {"list"},
		"delimiter": {"/"},
		// A partition holds many blobs; the walk wants the newest, and the
		// service returns them in name order, so this stays small on purpose.
		"maxresults": {"100"},
	}
	if prefix != "" {
		query.Set("prefix", prefix)
	}
	var result blobEnumeration
	if err := c.get(ctx, base+"/"+url.PathEscape(container)+"?"+query.Encode(), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// get issues one authenticated GET and decodes the XML body.
func (c *dataPlaneClient) get(ctx context.Context, address string, out any) error {
	request, err := runtime.NewRequest(ctx, http.MethodGet, address)
	if err != nil {
		return &collect.Failure{Message: "the request could not be built", Err: err}
	}
	request.Raw().Header.Set("x-ms-version", rules.MustOperation("storageDataPlane"))
	response, err := c.pipeline.Do(request)
	if err != nil {
		return &collect.Failure{Message: "the request failed", Err: err}
	}
	defer response.Body.Close() //nolint:errcheck // the body is drained below
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return dataPlaneFailure(response)
	}
	if err := xml.NewDecoder(response.Body).Decode(out); err != nil {
		return &collect.Failure{Message: "the response could not be decoded", Err: err}
	}
	return nil
}

// The subset of the listing schema this walk reads.
type containerEnumeration struct {
	Containers struct {
		Items []struct {
			Name       string `xml:"Name"`
			Properties struct {
				LeaseState string `xml:"LeaseState"`
			} `xml:"Properties"`
		} `xml:"Container"`
	} `xml:"Containers"`
}

type blobEnumeration struct {
	Blobs struct {
		Items []struct {
			Name       string `xml:"Name"`
			Properties struct {
				LastModified rfc1123 `xml:"Last-Modified"`
			} `xml:"Properties"`
		} `xml:"Blob"`
		Prefixes []blobPrefix `xml:"BlobPrefix"`
	} `xml:"Blobs"`
}

type blobPrefix struct {
	Name string `xml:"Name"`
}

// rfc1123 is the date format the storage data plane returns.
type rfc1123 struct{ parsed time.Time }

func (t *rfc1123) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var text string
	if err := decoder.DecodeElement(&text, &start); err != nil {
		return err
	}
	// A date this tool cannot parse is left zero rather than guessed at; the
	// walk then reports no write from that blob instead of a wrong one.
	if parsed, err := time.Parse(time.RFC1123, text); err == nil {
		t.parsed = parsed.UTC()
	}
	return nil
}

func (t rfc1123) Time() time.Time { return t.parsed }

// dataPlaneFailure classifies a data-plane error. The storage service puts its
// error code in a header, so there is no body to parse and nothing of the
// caller's data is read on the failure path.
func dataPlaneFailure(response *http.Response) error {
	return &collect.Failure{
		StatusCode: response.StatusCode,
		ErrorCode:  response.Header.Get("x-ms-error-code"),
		Message:    "the data-plane request was refused",
	}
}
