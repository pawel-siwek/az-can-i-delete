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
	"unicode/utf8"

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
			// A non-JSON answer is kept verbatim rather than guessed at; it is
			// still a thing the code has to cope with on replay.
			value = string(body)
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
		if value := response.Header.Get(name); value != "" {
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
			if redactedKeys[lower(key)] {
				out[key] = blank(inner)
				continue
			}
			out[key] = redact(inner)
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

// sanitize is the recorder's half of ADR-0007, applied to every string rather
// than only the three that are blanked.
//
// Blanking the fields that carry somebody's names is not enough on its own: a
// resource body is Azure's structure but its leaves are text a stranger may
// have chosen, and a control character or a lone surrogate committed into a
// fixture is a thing a reader's terminal executes rather than shows. So every
// string loses what is not text before it is written.
//
// It does not truncate, which the report boundary does. A report is read by a
// person and a long value there is noise; a fixture is replayed through the
// code, and a resource id or a token cut at 128 runes would be a recording of
// something Azure never said.
func sanitize(value string) string {
	if utf8.ValidString(value) && strings.IndexFunc(value, unprintable) < 0 {
		return value
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unprintable(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(value, ""))
}

// unprintable reports a rune that is not text: a control character other than
// the two a JSON string may legitimately carry, or an unassigned surrogate.
func unprintable(r rune) bool {
	if r == '\t' || r == '\n' {
		return false
	}
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r >= 0xd800 && r <= 0xdfff)
}

// blank keeps a redacted field's shape and loses its content: a collector that
// counts tags must still see how many there were.
func blank(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key := range typed {
			out[key] = Redacted
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

func lower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'A' && r <= 'Z' {
			out[i] = r + ('a' - 'A')
		}
	}
	return string(out)
}

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
