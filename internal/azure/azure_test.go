package azure_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	subscription = "00000000-0000-0000-0000-000000000001"
	resourceID   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/disk1"
	groupID      = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo"
)

// staticCredential stands in for a real credential. No test may reach an
// identity provider, and no fake may model an account key.
type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type request struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   map[string]any
}

// server is a fake management endpoint. It answers by path suffix, which keeps
// each test's expectations next to the call it is about.
type server struct {
	t         *testing.T
	responses map[string]func(w http.ResponseWriter, r *http.Request)
	requests  []request
}

func newServer(t *testing.T) (*server, *azure.Client) {
	t.Helper()
	s := &server{t: t, responses: map[string]func(http.ResponseWriter, *http.Request){}}
	httpServer := httptest.NewTLSServer(s)
	t.Cleanup(httpServer.Close)
	client, err := azure.New(azure.Options{
		Endpoint:   httpServer.URL,
		Credential: staticCredential{},
		// The test server's own client trusts its certificate; nothing here
		// disables verification.
		Transport: httpServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, client
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	recorded := request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
	if r.Body != nil {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			recorded.Body = body
		}
	}
	s.requests = append(s.requests, recorded)
	for suffix, handler := range s.responses {
		if strings.HasSuffix(r.URL.Path, suffix) {
			handler(w, r)
			return
		}
	}
	http.Error(w, `{"error":{"code":"NotFound","message":"no canned response"}}`, http.StatusNotFound)
}

func (s *server) answer(suffix string, body string) {
	s.responses[suffix] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func (s *server) fail(suffix string, status int, code string, header map[string]string) {
	s.responses[suffix] = func(w http.ResponseWriter, _ *http.Request) {
		for key, value := range header {
			w.Header().Set(key, value)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"service text"}}`))
	}
}

func (s *server) last() request {
	s.t.Helper()
	if len(s.requests) == 0 {
		s.t.Fatal("no request was issued")
	}
	return s.requests[len(s.requests)-1]
}

func TestGetSendsThePinnedAPIVersion(t *testing.T) {
	s, client := newServer(t)
	s.answer("/disks/disk1", `{"id":"`+resourceID+`","name":"disk1","type":"Microsoft.Compute/disks",
		"tags":{"owner":"platform"},"properties":{"provisioningState":"Succeeded","diskState":"Unattached"}}`)
	resource, err := client.ARM().Get(context.Background(), resourceID, "2026-03-02")
	if err != nil {
		t.Fatal(err)
	}
	if resource.ProvisioningState != "Succeeded" || resource.Tags["owner"] != "platform" ||
		resource.Properties["diskState"] != "Unattached" {
		t.Fatalf("resource = %+v, want the normalized body", resource)
	}
	if got := s.last().Query["api-version"]; len(got) != 1 || got[0] != "2026-03-02" {
		t.Errorf("api-version = %v, want the pinned version", got)
	}
}

func TestMissingResourceIsReportedAsNotFound(t *testing.T) {
	s, client := newServer(t)
	s.fail("/disks/disk1", http.StatusNotFound, "ResourceNotFound", nil)
	_, err := client.ARM().Get(context.Background(), resourceID, "2026-03-02")
	if !collect.NotFound(err) {
		t.Fatalf("err = %v, want a recognizable 404", err)
	}
}

func TestServiceErrorsBecomeClassifiableFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		header map[string]string
		want   verdict.UnknownCode
		retry  time.Duration
	}{
		{"forbidden", http.StatusForbidden, "AuthorizationFailed", nil, verdict.UnkPermission, 0},
		{"throttled", http.StatusTooManyRequests, "TooManyRequests", map[string]string{"Retry-After": "13"}, verdict.UnkThrottled, 13 * time.Second},
		{"unsupported", http.StatusBadRequest, "NoSupportedApiVersion", nil, verdict.UnkUnsupported, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, client := newServer(t)
			s.fail("/locks", c.status, c.code, c.header)
			_, err := client.ARM().Locks(context.Background(), resourceID)
			unknown := collect.Classify(err)
			if unknown.Code != c.want || unknown.HTTPStatus != c.status || unknown.ErrorCode != c.code {
				t.Fatalf("classified %v as %+v, want %s", err, unknown, c.want)
			}
			if unknown.Message == "service text" {
				t.Error("the service message must not become the tool's explanation")
			}
			if hint, retryable := collect.RetryAfter(err); c.retry != 0 && (!retryable || hint != c.retry) {
				t.Errorf("retry hint = %v/%v, want %v", hint, retryable, c.retry)
			}
		})
	}
}

func TestLocksAndDenyAssignments(t *testing.T) {
	s, client := newServer(t)
	s.answer("/locks", `{"value":[{"id":"/l1","name":"keep","properties":{"level":"CanNotDelete"}}]}`)
	s.answer("/denyAssignments", `{"value":[
		{"id":"/d1","properties":{"denyAssignmentName":"managed","permissions":[{"actions":["*"],"notActions":[]}]}},
		{"id":"/d2","properties":{"denyAssignmentName":"reads","permissions":[{"actions":["*/read"],"notActions":[]}]}},
		{"id":"/d3","properties":{"denyAssignmentName":"exempt","permissions":[{"actions":["*/delete"],"notActions":["*/delete"]}]}}]}`)
	locks, err := client.ARM().Locks(context.Background(), resourceID)
	if err != nil || len(locks) != 1 || locks[0].Level != "CanNotDelete" {
		t.Fatalf("locks = %+v, %v", locks, err)
	}
	if version := s.last().Query["api-version"][0]; version != "2020-05-01" {
		t.Errorf("locks api-version = %s, want the pinned 2020-05-01", version)
	}
	assignments, err := client.ARM().DenyAssignments(context.Background(), resourceID)
	if err != nil || len(assignments) != 3 {
		t.Fatalf("deny assignments = %+v, %v", assignments, err)
	}
	if !assignments[0].BlocksDelete || assignments[1].BlocksDelete || assignments[2].BlocksDelete {
		t.Errorf("only a wildcard or delete action without an exemption blocks: %+v", assignments)
	}
	if filter := s.last().Query["$filter"]; len(filter) != 1 || filter[0] != "atScope()" {
		t.Errorf("deny assignments must be filtered atScope(), got %v", filter)
	}
}

func TestDeploymentsAreNormalizedForTheAgeChain(t *testing.T) {
	s, client := newServer(t)
	s.answer("/deployments", `{"value":[{"name":"main","properties":{"timestamp":"2026-08-01T10:00:00Z",
		"provisioningState":"Succeeded","outputResources":[{"id":"`+resourceID+`"}]}}]}`)
	deployments, err := client.ARM().Deployments(context.Background(), groupID, 200)
	if err != nil || len(deployments) != 1 {
		t.Fatalf("deployments = %+v, %v", deployments, err)
	}
	got := deployments[0]
	if got.Name != "main" || got.Status != "Succeeded" || got.OutputResources[0] != resourceID ||
		!got.Timestamp.Equal(time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("deployment = %+v", got)
	}
	if top := s.last().Query["$top"]; len(top) != 1 || top[0] != "200" {
		t.Errorf("$top = %v, want the page budget", top)
	}
}

func TestPagedListingIsFollowedAndTruncationIsReported(t *testing.T) {
	s, client := newServer(t)
	pages := 0
	s.responses["/locks"] = func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set("Content-Type", "application/json")
		next := "https://" + r.Host + r.URL.Path + "?api-version=2020-05-01&page=" + string(rune('0'+pages))
		_, _ = w.Write([]byte(`{"value":[{"id":"/l` + string(rune('0'+pages)) + `","properties":{"level":"ReadOnly"}}],
			"nextLink":"` + next + `"}`))
	}
	locks, err := client.ARM().Locks(context.Background(), resourceID)
	if !errors.Is(err, collect.ErrTruncated) {
		t.Fatalf("err = %v, want a truncated listing", err)
	}
	if len(locks) != azure.MaxPages || pages != azure.MaxPages {
		t.Fatalf("followed %d pages and kept %d locks, want %d", pages, len(locks), azure.MaxPages)
	}
	if collect.Classify(err).Code != verdict.UnkPartial {
		t.Error("a truncated listing must classify as unknown(partial)")
	}
}

func TestGraphQueryScopeAndTruncation(t *testing.T) {
	s, client := newServer(t)
	s.answer("/resources", `{"count":1,"totalRecords":1,"resultTruncated":"true","$skipToken":"next",
		"data":[{"id":"`+resourceID+`"}]}`)
	rows, err := client.Graph().Query(context.Background(), collect.Query{
		Text: "resources | where id =~ 'x'", Subscriptions: []string{subscription}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 1 || !rows.Truncated || rows.SkipToken != "next" {
		t.Fatalf("rows = %+v, want the row plus its truncation markers", rows)
	}
	body := s.last().Body
	if subscriptions, _ := body["subscriptions"].([]any); len(subscriptions) != 1 || subscriptions[0] != subscription {
		t.Errorf("query scope = %v, want exactly the target subscription", body["subscriptions"])
	}
	if _, err := client.Graph().Query(context.Background(), collect.Query{Text: "resources"}); err == nil {
		t.Error("a query without an explicit subscription scope must be refused")
	}
}

func TestMetricsWindowAndPoints(t *testing.T) {
	s, client := newServer(t)
	s.answer("/metrics", `{"value":[{"name":{"value":"Transactions"},"unit":"Count","timeseries":[
		{"metadatavalues":[{"name":{"value":"apiname"},"value":"PutBlob"}],
		 "data":[{"timeStamp":"2026-09-01T00:00:00Z","total":12},{"timeStamp":"2026-09-02T00:00:00Z"}]}]}]}`)
	end := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	result, err := client.Metrics().Metrics(context.Background(), collect.MetricQuery{
		ResourceURI: resourceID, Names: []string{"Transactions"}, Aggregation: "Total", Interval: "P1D",
		Window: verdict.Window{Start: end.AddDate(0, 0, -30), End: end, Days: 30, Grain: "P1D"},
	})
	if err != nil || len(result.Series) != 1 {
		t.Fatalf("result = %+v, %v", result, err)
	}
	series := result.Series[0]
	if len(series.Points) != 1 || series.Points[0].Value != 12 || series.Dimensions["apiname"] != "PutBlob" {
		t.Fatalf("series = %+v, want only the bucket that carried a value", series)
	}
	query := s.last().Query
	if want := "2026-08-22T00:00:00Z/2026-09-21T00:00:00Z"; query["timespan"][0] != want {
		t.Errorf("timespan = %v, want the explicit window %s", query["timespan"], want)
	}
	if query["api-version"][0] != "2024-02-01" || query["interval"][0] != "P1D" {
		t.Errorf("metrics request = %v, want the pinned version and interval", query)
	}
	if _, err := client.Metrics().Metrics(context.Background(), collect.MetricQuery{
		ResourceURI: resourceID, Names: []string{"Transactions"}, Aggregation: "Total"}); err == nil {
		t.Error("a metrics request without a window must be refused")
	}
}

func TestActivityLogNormalization(t *testing.T) {
	s, client := newServer(t)
	s.answer("/values", `{"value":[
		{"eventTimestamp":"2026-09-18T08:00:00Z","resourceId":"`+resourceID+`","caller":"alice@example.com",
		 "operationName":{"value":"Microsoft.Compute/disks/write"},"status":{"value":"Succeeded"},
		 "subStatus":{"value":"Created"},"httpRequest":{"method":"PUT"},"properties":{"statusCode":"Created"}},
		{"eventTimestamp":"2026-09-10T08:00:00Z","resourceId":"`+resourceID+`","caller":"11111111-1111-1111-1111-111111111111",
		 "operationName":{"value":"Microsoft.Compute/disks/write"},"status":{"value":"Succeeded"},
		 "claims":{"idtyp":"app","appid":"AAAAAAAA-0000-0000-0000-00000000000A"}},
		{"eventTimestamp":"2026-09-09T08:00:00Z","resourceId":"`+resourceID+`","caller":"x",
		 "operationName":{"value":"Microsoft.Compute/disks/write"},"status":{"value":"Succeeded"},
		 "claims":{"appid":"not a guid"}}]}`)
	end := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	log, err := client.ActivityLog().Events(context.Background(), resourceID,
		verdict.Window{Start: end.AddDate(0, 0, -90), End: end, Days: 90, Grain: "P1D"})
	if err != nil || len(log.Events) != 3 {
		t.Fatalf("log = %+v, %v", log, err)
	}
	if log.Days != 90 || log.Truncated {
		t.Errorf("coverage = %d days truncated=%v, want the requested complete window", log.Days, log.Truncated)
	}
	first := log.Events[0]
	if first.StatusCode != "Created" || first.SubStatus != "Created" || first.CallerType != "user" ||
		first.HTTPMethod != "PUT" {
		t.Fatalf("event = %+v, want the age chain's creation markers and the caller class", first)
	}
	if log.Events[1].CallerType != "servicePrincipal" {
		t.Errorf("an application claim must classify as a service principal, got %q", log.Events[1].CallerType)
	}
	// The application id is kept only when it is one, and lower-cased so
	// two spellings of the same writer compare equal.
	if log.Events[1].AppID != "aaaaaaaa-0000-0000-0000-00000000000a" || log.Events[2].AppID != "" {
		t.Errorf("app ids = %q, %q", log.Events[1].AppID, log.Events[2].AppID)
	}
	if filter := s.last().Query["$filter"][0]; !strings.Contains(filter, "resourceUri eq '"+resourceID+"'") ||
		!strings.Contains(filter, "eventTimestamp ge '2026-06-23T00:00:00Z'") {
		t.Errorf("filter = %q, want the resource and the explicit window", filter)
	}
	if _, err := client.ActivityLog().Events(context.Background(), "/providers/Microsoft.Management/managementGroups/mg",
		verdict.Window{Start: end.AddDate(0, 0, -90), End: end, Days: 90}); err == nil {
		t.Error("the Activity Log is subscription-scoped and must refuse other scopes")
	}
}

func TestTheAdapterDoesNotRetryOnItsOwn(t *testing.T) {
	s, client := newServer(t)
	attempts := 0
	s.responses["/locks"] = func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"ServiceUnavailable","message":"x"}}`))
	}
	if _, err := client.ARM().Locks(context.Background(), resourceID); err == nil {
		t.Fatal("a 503 must surface as a failure")
	}
	// Retries, their Retry-After waits and the run budget belong to
	// internal/collect, so the adapter must issue exactly one request.
	if attempts != 1 {
		t.Fatalf("the adapter issued %d attempts, want exactly one", attempts)
	}
}

func TestSubResourceBodyIsKept(t *testing.T) {
	s, client := newServer(t)
	// A virtual machine's instance view is its own payload rather than a
	// resource wrapping one; losing it would report an unread check as absent.
	s.answer("/instanceView", `{"statuses":[{"code":"PowerState/deallocated","displayStatus":"VM deallocated"}]}`)
	resource, err := client.ARM().Get(context.Background(), resourceID+"/instanceView", "2026-04-01")
	if err != nil {
		t.Fatal(err)
	}
	statuses, ok := resource.Properties["statuses"].([]any)
	if !ok || len(statuses) != 1 {
		t.Fatalf("instance view = %+v, want its statuses", resource.Properties)
	}
	if resource.ID != resourceID+"/instanceView" {
		t.Errorf("id = %q, want the requested path", resource.ID)
	}
}

// A site, a plan or a network resource returns no systemData on GET. ARM's
// resource list with $expand=createdTime answers for every type; the fourth
// end-to-end run showed those resources with no age source without it.
func TestCreatedTimeIsReadFromTheResourceList(t *testing.T) {
	const slotID = groupID + "/providers/Microsoft.Web/sites/app1/slots/staging"
	s, client := newServer(t)
	s.answer(groupID+"/resources", `{"value":[
		{"id":"`+strings.ToUpper(slotID)+`","createdTime":"2026-09-24T21:16:03.1234567Z"},
		{"id":"`+groupID+`/providers/Microsoft.Web/sites/app1","createdTime":"2020-01-01T00:00:00Z"}]}`)
	created, err := client.ARM().CreatedTime(context.Background(), slotID)
	if err != nil || created == nil || !created.Equal(time.Date(2026, 9, 24, 21, 16, 3, 123456700, time.UTC)) {
		t.Fatalf("created = %v, %v; want the slot's own creation time", created, err)
	}
	query := s.last().Query
	if query["$filter"][0] != "name eq 'app1/staging'" || query["$expand"][0] != "createdTime" ||
		query["api-version"][0] == "" {
		t.Errorf("query = %v, want the slot named by its list name, createdTime expanded and a pinned version", query)
	}

	missing, err := client.ARM().CreatedTime(context.Background(), groupID+"/providers/Microsoft.Web/sites/other")
	if err != nil || missing != nil {
		t.Errorf("a resource the list does not return = %v, %v; want none and no error", missing, err)
	}
}
