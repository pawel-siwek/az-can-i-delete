package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"gopkg.in/yaml.v3"
)

// Redacted replaces every value a recording must not carry.
const Redacted = "REDACTED"

// redactedKeys are the fields whose values are somebody's, not Azure's
// structure: names a stranger chose, the identity that made a call, the claims
// in their token. A recording is committed to a repository and read by people
// who were never in that tenant, so these never survive the recorder.
//
// This is narrower than the report boundary, which classifies free-form text
// and publishes it under `untrusted` (ADR-0007). A fixture has no reader to
// warn, so it does not classify: it deletes.
var redactedKeys = map[string]bool{"tags": true, "caller": true, "claims": true}

// Recorder writes every response it passes through to a fixture directory.
//
// It is the only way a fixture is made. Writing one by hand would mean writing
// what somebody believes Azure returns, and the whole point of a recording is
// that nobody had to believe anything.
type Recorder struct {
	dir   string
	inner http.RoundTripper
}

// Record wraps a transport so that its answers are kept.
func Record(dir string, inner http.RoundTripper) (*Recorder, error) {
	if dir == "" {
		return nil, fmt.Errorf("a recording directory is required")
	}
	if err := os.MkdirAll(filepath.Join(dir, responsesDir), 0o750); err != nil {
		return nil, err
	}
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &Recorder{dir: dir, inner: inner}, nil
}

// RoundTrip performs the request and keeps the answer.
func (r *Recorder) RoundTrip(request *http.Request) (*http.Response, error) {
	// Read the question before sending it: Resource Graph asks everything on
	// one path, so the body is the only thing that tells two recordings apart.
	question, err := Body(request)
	if err != nil {
		return nil, err
	}
	response, err := r.inner.RoundTrip(request)
	if err != nil || response == nil {
		return response, err
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	// The caller still gets the body it would have got; only the copy on disk
	// is redacted.
	response.Body = io.NopCloser(bytes.NewReader(body))

	if writeErr := r.write(request, question, response, body); writeErr != nil {
		return nil, writeErr
	}
	return response, nil
}

func (r *Recorder) write(request *http.Request, question []byte, response *http.Response, body []byte) error {
	var value any
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &value); err != nil {
			// A non-JSON answer is kept rather than guessed at; it is still a
			// thing the code has to cope with on replay. It is text like any
			// other, so it passes the same filter.
			value = sanitize(string(body))
		} else {
			value = redact(value)
		}
	}
	encoded, err := json.MarshalIndent(
		recordedValue{Status: response.StatusCode, Headers: headers(response), Body: value}, "", "  ")
	if err != nil {
		return err
	}
	name := filepath.Join(r.dir, responsesDir, Key(request.Method, request.URL, question)+".json")
	return os.WriteFile(name, append(encoded, '\n'), 0o600)
}

// keptHeaders are the response headers a replay needs.
//
// The specification's shape is `{k: v}` without saying which, and "all of
// them" is the wrong reading: a response carries request ids, a session id and
// a timestamp that identify one call in one tenant on one day. None of that
// helps a replay, and a recording is committed to a repository. So the named
// ones are the ones the code downstream actually reads — how to decode the
// body, how long to wait, and where a long-running operation continues, which
// SPEC 7.5 requires a fixture to carry for pollers.
var keptHeaders = []string{
	"Content-Type", "Retry-After", "Azure-AsyncOperation", "Location", "x-ms-error-code",
}

// headers keeps the few a replay needs, in a stable order.
func headers(response *http.Response) map[string]string {
	kept := map[string]string{}
	for _, name := range keptHeaders {
		// A header is Azure's text too. `Retry-After` is a number and
		// `Azure-AsyncOperation` is a URL the service chose, and neither is
		// exempt from being read by a person looking at the fixture.
		if value := sanitize(response.Header.Get(name)); value != "" {
			kept[name] = value
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// recordedValue is `recorded` while it is still a Go value rather than raw
// JSON, which is what the recorder has and the reader does not need.
type recordedValue struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    any               `json:"body"`
}

// redact walks a decoded response and removes what is not Azure's structure.
func redact(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			// A key is text on the page too, and a tag's key is one a
			// stranger chose. Redacting the value and copying the name it
			// was filed under would leave half the sentence.
			clean := sanitize(key)
			if redactedKeys[lower(key)] {
				out[clean] = blank(inner)
				continue
			}
			out[clean] = redact(inner)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, inner := range typed {
			out = append(out, redact(inner))
		}
		return out
	case string:
		return sanitize(typed)
	default:
		return value
	}
}

// blank keeps a redacted field's shape and loses its content: a collector that
// counts tags must still see how many there were.
func blank(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key := range typed {
			out[sanitize(key)] = Redacted
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for range typed {
			out = append(out, Redacted)
		}
		return out
	case nil:
		return nil
	default:
		return Redacted
	}
}

func lower(s string) string { return strings.ToLower(s) }

// sanitize applies ADR-0007's character contract to a recorded string, and
// deliberately not its length cap. ADR-0016 is the record of that difference.
//
// It calls the boundary's own implementation rather than restating the rules.
// A second copy of "which Unicode categories are not text" would agree with
// the first until somebody fixed one of them.
func sanitize(value string) string { return output.Sanitized(value) }

// WriteManifest records what the run was, and what it produced. The expected
// verdict is written from the run rather than typed in, so a fixture always
// starts out agreeing with itself; the test that replays it is what notices
// when the code stops agreeing later.
func (r *Recorder) WriteManifest(manifest Manifest) error {
	if manifest.Now.IsZero() {
		return fmt.Errorf("a recording needs the cutoff it was made at")
	}
	manifest.Now = manifest.Now.UTC().Truncate(time.Second)
	body, err := yaml.Marshal(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.dir, ManifestName), body, 0o600)
}
