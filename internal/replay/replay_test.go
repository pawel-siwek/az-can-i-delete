package replay_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
)

// A recording is only worth shipping while it still demonstrates the thing it
// was recorded to demonstrate. This replays every embedded scenario through
// the real adapters, collectors and verdict engine, and holds the result to
// the manifest — so a change that alters a verdict fails here rather than in
// front of whoever is being shown the tool.
func TestEveryScenarioStillShowsWhatItClaims(t *testing.T) {
	slugs := replay.Scenarios()
	if len(slugs) == 0 {
		t.Fatal("no scenarios are embedded, so this checked nothing")
	}
	for _, slug := range slugs {
		t.Run(slug, func(t *testing.T) {
			fixture, err := replay.Scenario(slug)
			if err != nil {
				t.Fatal(err)
			}
			report := replayed(t, fixture)

			expect := fixture.Manifest.Expect
			if got := text(report["verdict"]); got != expect.Verdict {
				t.Errorf("verdict = %q, the manifest says %q", got, expect.Verdict)
			}
			if got := text(report["reasonClass"]); got != expect.ReasonClass {
				t.Errorf("reasonClass = %q, the manifest says %q", got, expect.ReasonClass)
			}
			if got := textList(report["reasons"]); !reflect.DeepEqual(got, expect.Reasons) {
				t.Errorf("reasons = %v, the manifest says %v", got, expect.Reasons)
			}
			if replayed, _ := report["replay"].(bool); !replayed {
				t.Error("a replayed report must say so; nothing recorded may read as observed")
			}
		})
	}
}

func replayed(t *testing.T, fixture *replay.Fixture) map[string]any {
	t.Helper()
	client, err := azure.Recorded(fixture.Transport(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	runner := assess.New(collect.Clients{
		ARM: client.ARM(), Graph: client.Graph(),
		Metrics: client.Metrics(), ActivityLog: client.ActivityLog(),
	}, "dev")
	target, err := armid.Parse(fixture.Manifest.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	window := fixture.Manifest.Window
	if window == "" {
		window = "30d"
	}
	requested, err := assess.ParseWindow(window, fixture.Manifest.Now)
	if err != nil {
		t.Fatal(err)
	}
	outcome, checkErr := runner.Check(context.Background(), target, assess.Options{
		Requested: requested, Cutoff: fixture.Manifest.Now, Replay: true,
	})
	if checkErr != nil {
		t.Fatalf("the scenario did not replay: %v", checkErr)
	}
	return decode(t, outcome)
}

// A request nobody recorded must be an error. If it were an empty answer, a
// fixture that had drifted from the code would report absence — the exact
// failure ADR-0004 exists to prevent, arriving through the one path that is
// supposed to be safe.
func TestAnUnrecordedRequestIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	fixture, err := replay.Scenario(replay.Scenarios()[0])
	if err != nil {
		t.Fatal(err)
	}
	address, err := url.Parse("https://management.azure.com/subscriptions/x/nothing/was/recorded/here")
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.Transport().RoundTrip(&http.Request{Method: http.MethodGet, URL: address})
	if err == nil {
		t.Fatalf("a miss returned a response: %v", response)
	}
	if !strings.HasPrefix(err.Error(), "fixture miss: GET ") {
		t.Errorf("the error does not name the miss: %v", err)
	}
}

// The api-version is deliberately not part of a fixture's name. A pin lives in
// the rule table and may be corrected there (ADR-0008); a recording made under
// the old pin still answers the same question.
func TestTheKeyIgnoresTheApiVersionAndTheQueryOrder(t *testing.T) {
	first, err := url.Parse("https://host/p/Q?b=2&a=1&api-version=2020-01-01")
	if err != nil {
		t.Fatal(err)
	}
	second, err := url.Parse("https://host/p/q?a=1&b=2&api-version=2099-12-31")
	if err != nil {
		t.Fatal(err)
	}
	if replay.Key("GET", first, nil) != replay.Key("GET", second, nil) {
		t.Error("the same question got two names")
	}
	third, err := url.Parse("https://host/p/q?a=9&b=2")
	if err != nil {
		t.Fatal(err)
	}
	if replay.Key("GET", first, nil) == replay.Key("GET", third, nil) {
		t.Error("two different questions got one name")
	}
	if replay.Key("POST", first, nil) == replay.Key("GET", first, nil) {
		t.Error("a POST and a GET to one address got one name")
	}
}

// Resource Graph asks every question as a POST to one path. Without the body
// in the name, a recording keeps one of them and replays it to all of them.
func TestTwoResourceGraphQuestionsGetTwoNames(t *testing.T) {
	address, err := url.Parse("https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01")
	if err != nil {
		t.Fatal(err)
	}
	visible := []byte(`{"query":"resources | where id =~ 'x' | project id, type"}`)
	backups := []byte(`{"query":"recoveryservicesresources | where type =~ 'y'"}`)
	if replay.Key("POST", address, visible) == replay.Key("POST", address, backups) {
		t.Error("two different Resource Graph questions got one name")
	}
	again := []byte(`{"query":"resources | where id =~ 'x' | project id, type"}`)
	if replay.Key("POST", address, visible) != replay.Key("POST", address, again) {
		t.Error("one question got two names")
	}
}

// Everything a recording carries about somebody — the names they chose, who
// called, what their token claimed — is gone before it reaches the repository.
// This reads the committed files rather than the loader, because what matters
// is what is in the repository, not what a reader does with it afterwards.
func TestARecordingCarriesNobodysNames(t *testing.T) {
	checked := 0
	err := fs.WalkDir(os.DirFS("scenarios"), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return err
		}
		body, readErr := fs.ReadFile(os.DirFS("scenarios"), name)
		if readErr != nil {
			return readErr
		}
		var value any
		if jsonErr := json.Unmarshal(body, &value); jsonErr != nil {
			return fmt.Errorf("%s is not valid JSON: %w", name, jsonErr)
		}
		checked++
		for _, leak := range unredacted(value, "") {
			t.Errorf("%s still carries %s", name, leak)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no recorded responses were read, so this checked nothing")
	}
}

// unredacted returns the paths of any value under a redacted key that is not
// the redaction marker.
func unredacted(value any, at string) []string {
	var found []string
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			where := at + "." + key
			if key == "tags" || key == "caller" || key == "claims" {
				found = append(found, notRedacted(inner, where)...)
				continue
			}
			found = append(found, unredacted(inner, where)...)
		}
	case []any:
		for i, inner := range typed {
			found = append(found, unredacted(inner, fmt.Sprintf("%s[%d]", at, i))...)
		}
	}
	return found
}

func notRedacted(value any, at string) []string {
	switch typed := value.(type) {
	case map[string]any:
		var found []string
		for key, inner := range typed {
			found = append(found, notRedacted(inner, at+"."+key)...)
		}
		return found
	case []any:
		var found []string
		for i, inner := range typed {
			found = append(found, notRedacted(inner, fmt.Sprintf("%s[%d]", at, i))...)
		}
		return found
	case nil:
		return nil
	case string:
		if typed == replay.Redacted {
			return nil
		}
		return []string{at + " = " + typed}
	default:
		return []string{fmt.Sprintf("%s = %v", at, typed)}
	}
}

// The redaction is only worth having if it fires, so here is what it is for.
func TestTheRedactionCheckCatchesARealName(t *testing.T) {
	var value any
	if err := json.Unmarshal([]byte(`{"properties":{"tags":{"owner":"someone@example.test"}}}`), &value); err != nil {
		t.Fatal(err)
	}
	if found := unredacted(value, ""); len(found) == 0 {
		t.Error("a tag value that nobody redacted was not noticed")
	}
}
