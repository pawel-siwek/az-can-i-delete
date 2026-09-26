package replay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
)

var update = flag.Bool("update", false, "re-record the embedded demo scenarios")

// Every scenario is in the same subscription and reads the same instant, so a
// recorded window and a recorded timestamp can be read against each other by
// eye, and one scenario's fixtures are recognisable next to another's.
const (
	subscription    = "00000000-0000-0000-0000-000000000001"
	resourceGroupID = "/subscriptions/" + subscription + "/resourceGroups/rg-demo"
)

var cutoff = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func ago(days int) string { return cutoff.AddDate(0, 0, -days).Format(time.RFC3339) }

// answers is a scenario's Azure: a body per request, matched on the path's
// suffix and, where one path serves several questions, a distinguishing piece
// of the query or of the body. It exists only to be recorded from; nothing in
// the product reads it.
//
// There is no catch-all. A request no answer matches fails the recording, which
// is what SPEC 7.6 promises and the only reason a fixture can be trusted: a new
// signal that asks a question nobody answered has to be answered deliberately,
// rather than recorded as having found nothing.
type answers struct {
	title  string
	id     string
	now    time.Time
	window string
	bodies []answer
}

type answer struct {
	match    string // path suffix
	query    string // a substring the decoded URL query must contain, when one path serves several questions
	contains string // a substring the request body must contain, which is how Resource Graph questions are told apart
	body     string
}

func (a answers) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ := io.ReadAll(r.Body)
		// The query is matched decoded, so an answer can name the metric or
		// the filter it is for in the words Azure's own documentation uses
		// rather than in percent escapes.
		asked, err := url.QueryUnescape(r.URL.RawQuery)
		if err != nil {
			asked = r.URL.RawQuery
		}
		for _, candidate := range a.bodies {
			if !strings.HasSuffix(strings.ToLower(r.URL.Path), strings.ToLower(candidate.match)) {
				continue
			}
			if candidate.query != "" && !strings.Contains(asked, candidate.query) {
				continue
			}
			if candidate.contains != "" && !strings.Contains(string(sent), candidate.contains) {
				continue
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(candidate.body))
			return
		}
		// Nothing is served here on purpose. A question this scenario does
		// not answer is a question whose answer nobody decided, and recording
		// it as an empty page would put an absence in a fixture that no Azure
		// ever reported (ADR-0004).
		t.Errorf("the scenario has no answer for %s %s?%s %s", r.Method, r.URL.Path, asked, sent)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NotFound","message":"the scenario has no answer for this"}}`))
	})
}

// record runs the real assessment against the scenario's answers and keeps
// every response, then writes the manifest from what the run actually
// produced. A fixture is never typed in: it is what the code saw.
func record(t *testing.T, slug string, scenario answers) {
	t.Helper()
	dir := filepath.Join("scenarios", slug)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(scenario.handler(t))
	defer server.Close()

	recorder, err := replay.Record(dir, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	client, err := recordedClient(server.URL, recorder)
	if err != nil {
		t.Fatal(err)
	}
	report := run(t, client, scenario)

	manifest := replay.Manifest{
		ResourceID: scenario.id, Now: scenario.now, Title: scenario.title,
		Window:         scenario.window,
		SubscriptionID: subscriptionOf(scenario.id),
		Expect: replay.Expect{
			Verdict: text(report["verdict"]), ReasonClass: text(report["reasonClass"]),
			Reasons: textList(report["reasons"]),
		},
	}
	if err := recorder.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s recorded: %s / %s", slug, manifest.Expect.Verdict, manifest.Expect.ReasonClass)
	for _, reason := range manifest.Expect.Reasons {
		t.Logf("    %s", reason)
	}
}

func run(t *testing.T, client *azure.Client, scenario answers) map[string]any {
	t.Helper()
	runner := assess.New(collect.Clients{
		ARM: client.ARM(), Graph: client.Graph(),
		Metrics: client.Metrics(), ActivityLog: client.ActivityLog(),
	}, "dev")
	target, err := armid.Parse(scenario.id)
	if err != nil {
		t.Fatal(err)
	}
	window := scenario.window
	if window == "" {
		window = "30d"
	}
	requested, err := assess.ParseWindow(window, scenario.now)
	if err != nil {
		t.Fatal(err)
	}
	outcome, checkErr := runner.Check(context.Background(), target,
		assess.Options{Requested: requested, Cutoff: scenario.now})
	if checkErr != nil {
		t.Fatalf("the scenario did not assess: %v", checkErr)
	}
	return decode(t, outcome)
}

// decode reads the outcome through the public rendering path, which is also
// the one a user sees.
func decode(t *testing.T, outcome output.Outcome) map[string]any {
	t.Helper()
	var buffer bytes.Buffer
	if err := output.Render(&buffer, "json", []output.Outcome{outcome}); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &value); err != nil {
		t.Fatalf("%v: %s", err, buffer.String())
	}
	return value
}

func subscriptionOf(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) > 2 {
		return parts[2]
	}
	return ""
}

func text(value any) string {
	s, _ := value.(string)
	return s
}

func textList(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// recordedClient points the adapters at a test server through the recorder.
// The scenario's Azure is an httptest server, so this needs an endpoint, which
// is the one thing azure.Recorded does not take: a real recording is replayed
// against the public endpoint it was made from.
func recordedClient(endpoint string, recorder *replay.Recorder) (*azure.Client, error) {
	return azure.New(azure.Options{
		Endpoint: endpoint, Credential: azure.RecordedCredential(), Transport: azure.Transport(recorder),
	})
}

// The scenarios docs/SPEC.md 7.6 names, each recorded from a real run of the
// real code. Adding one here is what puts it in `demo`; nothing else registers
// it.
func TestRecordScenarios(t *testing.T) {
	if !*update {
		t.Skip("run with -update to re-record the embedded scenarios")
	}
	for slug, scenario := range map[string]answers{
		"disk-yes-unattached":              diskYesUnattached(),
		"nic-yes-detached":                 nicYesDetached(),
		"vm-no-backup":                     vmNoBackup(),
		"storage-no-pe":                    storageNoPE(),
		"storage-tentative-defender":       storageTentativeDefender(),
		"storage-untrusted-tag":            storageUntrustedTag(),
		"site-tentative-linux-consumption": siteTentativeLinuxConsumption(),
	} {
		t.Run(slug, func(t *testing.T) { record(t, slug, scenario) })
	}
}
