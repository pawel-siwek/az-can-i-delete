// Package replay serves recorded Azure responses in place of Azure.
//
// It exists so that the whole assessment — the adapters, the collectors, the
// analyzers and the verdict — can be exercised end to end without a tenant,
// and so that a demonstration shows the real code reaching a real verdict
// rather than a screenshot of one.
//
// Two rules keep a recording from being mistaken for an observation. A replay
// is labelled as one everywhere it is reported, so nothing this package serves
// can be read as something the tool saw in Azure. And a request with no
// recorded answer is an error, never an empty result: a fixture that has
// drifted from the code must fail loudly rather than quietly turn a signal
// into an absence, which is the bug ADR-0004 exists to prevent.
package replay

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // naming a fixture file, not authenticating one
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	gopath "path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed all:scenarios
var embedded embed.FS

// ManifestName and responsesDir are the fixture layout of SPEC 7.5.
const (
	ManifestName = "manifest.yaml"
	responsesDir = "responses"
)

// Manifest describes what a fixture is a recording of.
type Manifest struct {
	// ResourceID is the target the recording was made against, so a replay
	// needs no argument and cannot be pointed at the wrong resource.
	ResourceID string `yaml:"resourceId"`
	// Now is the observation cutoff the recording was made at. Decide() takes
	// the cutoff as an input (ADR-0003), so replaying with the recorded cutoff
	// is what makes a replayed verdict reproducible years later.
	Now time.Time `yaml:"now"`
	// SubscriptionID is recorded so a replay can be checked against the
	// --subscription guard like any other run.
	SubscriptionID string `yaml:"subscriptionId"`
	// Window is the requested observation window, e.g. "30d". Empty means the
	// command's own default.
	Window string `yaml:"window,omitempty"`
	// Title is one line describing what the scenario shows.
	Title string `yaml:"title,omitempty"`
	// Expect is what this recording is supposed to produce. It is checked, so
	// a fixture that no longer demonstrates its point fails rather than
	// silently demonstrating something else.
	Expect Expect `yaml:"expect"`
}

// Expect is the verdict a fixture stands for.
type Expect struct {
	Verdict     string   `yaml:"verdict"`
	ReasonClass string   `yaml:"reasonClass"`
	Reasons     []string `yaml:"reasons"`
}

// Fixture is one loaded recording.
type Fixture struct {
	Manifest Manifest
	Name     string
	files    fs.FS
}

// Open loads a recording from a directory on disk.
func Open(dir string) (*Fixture, error) {
	if dir == "" {
		return nil, errors.New("a fixture directory is required")
	}
	return load(os.DirFS(dir), gopath.Base(gopath.Clean(dir)))
}

// Scenario loads one of the recordings shipped in the binary.
func Scenario(slug string) (*Fixture, error) {
	if !validSlug(slug) {
		return nil, fmt.Errorf("unknown scenario %q; run `demo` with no argument to list them", slug)
	}
	sub, err := fs.Sub(embedded, path.Join("scenarios", slug))
	if err != nil {
		return nil, fmt.Errorf("unknown scenario %q; run `demo` with no argument to list them", slug)
	}
	return load(sub, slug)
}

// Scenarios lists the recordings shipped in the binary, in name order.
func Scenarios() []string {
	entries, err := fs.ReadDir(embedded, "scenarios")
	if err != nil {
		return nil
	}
	var slugs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, statErr := fs.Stat(embedded, path.Join("scenarios", entry.Name(), ManifestName)); statErr != nil {
			continue
		}
		slugs = append(slugs, entry.Name())
	}
	sort.Strings(slugs)
	return slugs
}

func validSlug(slug string) bool {
	if slug == "" || strings.ContainsAny(slug, `/\.`) {
		return false
	}
	for _, known := range Scenarios() {
		if known == slug {
			return true
		}
	}
	return false
}

func load(files fs.FS, name string) (*Fixture, error) {
	body, err := fs.ReadFile(files, ManifestName)
	if err != nil {
		return nil, fmt.Errorf("the fixture has no %s: %w", ManifestName, err)
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("the fixture's %s could not be read: %w", ManifestName, err)
	}
	if manifest.ResourceID == "" || manifest.Now.IsZero() {
		return nil, fmt.Errorf("the fixture's %s needs a resourceId and a now", ManifestName)
	}
	return &Fixture{Manifest: manifest, Name: name, files: files}, nil
}

// Transport serves this fixture's recorded responses.
//
// It is a plain http.RoundTripper and this package knows nothing about the
// Azure SDK: ADR-0010 keeps every SDK type inside internal/azure, and a
// recording is a transport, not a client.
func (f *Fixture) Transport() http.RoundTripper { return &transport{files: f.files} }

// Key names the file holding the response to one request: the method, then a
// digest of the path, the query with api-version removed, and the request body
// where there is one.
//
// The version is left out on purpose — a pin can be corrected in the rule
// table (ADR-0008) without invalidating every recording made under the old
// one.
//
// The body is in, and SPEC 7.5 does not say so. It has to be. Resource Graph
// takes every question as a POST to one path with one query string, so seven
// different questions about a disk — is it visible, who manages its group,
// what changed, is it backed up, was an image built from it — all produce the
// same name. Recording them overwrites six; replaying serves the seventh to
// all seven askers. That does not fail: it answers confidently and wrongly,
// which is the one outcome this tool exists to prevent. A GET carries no body
// and is named exactly as the specification says.
func Key(method string, address *url.URL, body []byte) string {
	query := address.Query()
	query.Del("api-version")
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		values := append([]string(nil), query[key]...)
		sort.Strings(values)
		for _, value := range values {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}
	seed := strings.ToLower(address.Path) + "?" + strings.Join(parts, "&")
	if question := bytes.TrimSpace(body); len(question) > 0 {
		seed += "#" + string(question)
	}
	sum := sha1.Sum([]byte(seed)) //nolint:gosec // a file name
	return strings.ToUpper(method) + "_" + hex.EncodeToString(sum[:])
}

// Body reads a request's body without consuming it, so the same request can
// still be sent or replayed afterwards.
func Body(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	if request.GetBody != nil {
		fresh, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(fresh)
		_ = fresh.Close()
		if readErr != nil {
			return nil, readErr
		}
		// GetBody is not required to return a copy, and azcore's does not: it
		// rewinds and hands back the same reader, so reading it here leaves
		// the request with nothing to send. Give it an unread body back.
		if again, againErr := request.GetBody(); againErr == nil {
			request.Body = again
		} else {
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
		return body, nil
	}
	body, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// recorded is one response as it sits on disk.
type recorded struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body"`
}

type transport struct{ files fs.FS }

func (t *transport) RoundTrip(request *http.Request) (*http.Response, error) {
	question, err := Body(request)
	if err != nil {
		return nil, err
	}
	name := path.Join(responsesDir, Key(request.Method, request.URL, question)+".json")
	body, err := fs.ReadFile(t.files, name)
	if err != nil {
		// Never an empty answer. A collector that received one would report
		// absence, and an absence nobody observed is the failure this whole
		// tool exists to avoid.
		return nil, fmt.Errorf("fixture miss: %s %s", request.Method, request.URL.Path)
	}
	var response recorded
	if err := json.Unmarshal(body, &response); err != nil { //nolint:govet // shadowing the read error is intended
		return nil, fmt.Errorf("fixture %s could not be read: %w", name, err)
	}
	if response.Status == 0 {
		response.Status = http.StatusOK
	}
	payload := []byte(response.Body)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	header := http.Header{"Content-Type": []string{"application/json"}}
	for key, value := range response.Headers {
		header.Set(key, value)
	}
	return &http.Response{
		Status:        http.StatusText(response.Status),
		StatusCode:    response.Status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       request,
	}, nil
}
