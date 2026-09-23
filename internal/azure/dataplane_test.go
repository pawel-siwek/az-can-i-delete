package azure_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
)

const accountID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Storage/storageAccounts/sa1"

// blobServer is a fake blob endpoint that answers delimited listings from a
// map of prefix to response body.
type blobServer struct {
	t        *testing.T
	bodies   map[string]string
	status   int
	errCode  string
	requests []string
	headers  []string
}

func (s *blobServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	s.requests = append(s.requests, prefix)
	s.headers = append(s.headers, r.Header.Get("Authorization"))
	if s.status != 0 {
		w.Header().Set("x-ms-error-code", s.errCode)
		w.WriteHeader(s.status)
		return
	}
	body, found := s.bodies[prefix]
	if !found {
		body = `<EnumerationResults><Blobs></Blobs></EnumerationResults>`
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(body))
}

func newBlobServer(t *testing.T, s *blobServer) collect.DataPlaneClient {
	t.Helper()
	s.t = t
	httpServer := httptest.NewTLSServer(s)
	t.Cleanup(httpServer.Close)
	client, err := azure.DataPlane(azure.DataPlaneOptions{
		Endpoint:   httpServer.URL,
		Credential: staticCredential{},
		Transport:  httpServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// listing renders a delimited listing with the given sub-prefixes and blobs.
func listing(prefixes []string, blobs map[string]string) string {
	var b strings.Builder
	b.WriteString("<EnumerationResults><Blobs>")
	for name, modified := range blobs {
		b.WriteString("<Blob><Name>" + name + "</Name><Properties><Last-Modified>" + modified +
			"</Last-Modified></Properties></Blob>")
	}
	for _, prefix := range prefixes {
		b.WriteString("<BlobPrefix><Name>" + prefix + "</Name></BlobPrefix>")
	}
	b.WriteString("</Blobs></EnumerationResults>")
	return b.String()
}

// The walk descends one partition level per call, taking the latest at each
// level, and reports the newest write it reached.
func TestThePrefixWalkDescendsToTheNewestPartition(t *testing.T) {
	// A delimited listing returns the full prefix path, not the fragment below
	// the one that was asked for, so these fixtures spell them out.
	server := &blobServer{bodies: map[string]string{
		"":                  listing([]string{"y=2025/", "y=2026/"}, nil),
		"y=2026/":           listing([]string{"y=2026/m=08/", "y=2026/m=09/"}, nil),
		"y=2026/m=09/":      listing([]string{"y=2026/m=09/d=20/"}, nil),
		"y=2026/m=09/d=20/": listing([]string{"y=2026/m=09/d=20/h=13/"}, nil),
		"y=2026/m=09/d=20/h=13/": listing(nil, map[string]string{
			"y=2026/m=09/d=20/h=13/m=00/PT1H.json": "Sun, 20 Sep 2026 13:59:00 GMT",
		}),
	}}
	client := newBlobServer(t, server)

	prefix, err := client.PrefixWalk(context.Background(), accountID, "insights-logs-auditevent",
		collect.PrefixBudget{MaxCalls: 12, MaxTime: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !prefix.Complete {
		t.Error("the walk reached the end of the layout, so it is complete")
	}
	want := time.Date(2026, 9, 20, 13, 59, 0, 0, time.UTC)
	if !prefix.LastWrite.Equal(want) {
		t.Errorf("last write = %v, want %v", prefix.LastWrite, want)
	}
	if prefix.Path != "y=2026/m=09/d=20/h=13/" {
		t.Errorf("path = %q, want the deepest partition", prefix.Path)
	}
	// Five calls: the root and one per level. A walk that listed every blob
	// would be orders of magnitude more.
	if len(server.requests) != 5 {
		t.Errorf("made %d calls (%v), want one per partition level", len(server.requests), server.requests)
	}
	for _, header := range server.headers {
		if !strings.HasPrefix(header, "Bearer ") {
			t.Errorf("Authorization = %q, want a bearer token and nothing else", header)
		}
	}
}

// The budget stops the walk, and a stopped walk says so rather than reporting
// what it happened to have seen as the answer.
func TestTheWalkStopsAtItsCallBudget(t *testing.T) {
	server := &blobServer{bodies: map[string]string{
		"":             listing([]string{"y=2026/"}, nil),
		"y=2026/":      listing([]string{"y=2026/m=09/"}, nil),
		"y=2026/m=09/": listing([]string{"y=2026/m=09/d=20/"}, nil),
	}}
	client := newBlobServer(t, server)

	prefix, err := client.PrefixWalk(context.Background(), accountID, "logs",
		collect.PrefixBudget{MaxCalls: 2, MaxTime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if prefix.Complete {
		t.Error("a walk cut off by its budget must not report itself as complete")
	}
	if len(server.requests) != 2 {
		t.Errorf("made %d calls, want the two the budget allowed", len(server.requests))
	}
}

// A caller with no data access gets the refusal, classified. This is the
// failure that must never read as "nothing was written here".
func TestNoDataAccessIsAClassifiedFailure(t *testing.T) {
	client := newBlobServer(t, &blobServer{status: http.StatusForbidden, errCode: "AuthorizationPermissionMismatch"})

	_, err := client.PrefixWalk(context.Background(), accountID, "logs", collect.PrefixBudget{MaxCalls: 12})
	if err == nil {
		t.Fatal("a 403 must be an error, not an empty walk")
	}
	unknown := collect.Classify(err)
	if unknown.Code != "permission" {
		t.Errorf("classified as %q, want permission", unknown.Code)
	}
}

// The listing is delimited, so one call returns one level rather than every
// blob in the container.
func TestTheWalkAsksForOneLevelAtATime(t *testing.T) {
	var query url.Values
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		_, _ = w.Write([]byte(listing(nil, nil)))
	}))
	t.Cleanup(httpServer.Close)
	client, err := azure.DataPlane(azure.DataPlaneOptions{
		Endpoint: httpServer.URL, Credential: staticCredential{}, Transport: httpServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PrefixWalk(context.Background(), accountID, "logs", collect.PrefixBudget{MaxCalls: 1}); err != nil {
		t.Fatal(err)
	}
	if got := query.Get("delimiter"); got != "/" {
		t.Errorf("delimiter = %q, want / so one call returns one level", got)
	}
	if got := query.Get("restype"); got != "container" {
		t.Errorf("restype = %q, want container", got)
	}
}
