package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
)

// failIfItReachesAzure is the dependency set a replay must never use. A run
// that built the live runner would fail here rather than quietly succeed in
// front of somebody being shown the tool.
func failIfItReachesAzure(t *testing.T) Dependencies {
	t.Helper()
	deps := testDeps(nil, nil)
	deps.Runner = func(string, bool) (*assess.Runner, error) {
		t.Error("a replay built the live runner")
		return nil, errors.New("a replay must not reach Azure")
	}
	return deps
}

func TestDemoListsWhatItCanShow(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, failIfItReachesAzure(t), "demo")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	for _, slug := range replay.Scenarios() {
		if !strings.Contains(out, slug) {
			t.Errorf("the listing does not offer %s:\n%s", slug, out)
		}
	}
}

// Every scenario runs through the real command, because the command is what a
// person will actually type. A scenario that only works from a test harness is
// not a demonstration.
func TestDemoRunsEveryScenarioAndSaysItIsRecorded(t *testing.T) {
	t.Parallel()
	for _, slug := range replay.Scenarios() {
		t.Run(slug, func(t *testing.T) {
			t.Parallel()
			fixture, err := replay.Scenario(slug)
			if err != nil {
				t.Fatal(err)
			}
			code, out, errOut := run(t, failIfItReachesAzure(t), "demo", slug, "-o", "json")
			// A verdict is not an error: only --exit-on-verdict turns one
			// into an exit code, and a demonstration does not ask for that.
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, errOut)
			}
			var report map[string]any
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if got, _ := report["replay"].(bool); !got {
				t.Error("a replayed report did not say it was replayed")
			}
			if got, _ := report["verdict"].(string); got != fixture.Manifest.Expect.Verdict {
				t.Errorf("verdict = %q, the manifest says %q", got, fixture.Manifest.Expect.Verdict)
			}
		})
	}
}

// The table view is where somebody watching will see it, so the label has to
// be there and not only in the JSON nobody reads during a demonstration.
func TestTheTableSaysTheEvidenceWasRecorded(t *testing.T) {
	t.Parallel()
	_, out, _ := run(t, failIfItReachesAzure(t), "demo", replay.Scenarios()[0], "-o", "table")
	for _, want := range []string{"📼", "RECORDED"} {
		if !strings.Contains(out, want) {
			t.Errorf("the table does not say it is a recording (%q missing):\n%s", want, out)
		}
	}
}

func TestAnUnknownScenarioIsAUsageError(t *testing.T) {
	t.Parallel()
	code, _, errOut := run(t, failIfItReachesAzure(t), "demo", "no-such-scenario")
	if code != 2 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(errOut, "unknown scenario") {
		t.Errorf("the error does not say what was wrong: %q", errOut)
	}
}

// A slug is a directory name, so it is the one place a caller's text becomes a
// path. It does not get to leave the scenarios directory.
func TestAScenarioNameCannotEscapeTheScenarios(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"../../etc", "..", "a/b", `a\b`, "disk-yes-unattached/.."} {
		if _, err := replay.Scenario(name); err == nil {
			t.Errorf("%q was accepted as a scenario", name)
		}
	}
}

func TestCheckReplaysADirectory(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, failIfItReachesAzure(t),
		"check", "--fixture", "../replay/scenarios/disk-yes-unattached", "-o", "json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got, _ := report["replay"].(bool); !got {
		t.Error("a replayed report did not say it was replayed")
	}
}

// A recording names its own target. Being asked for one as well is how a
// demonstration ends up replaying one resource while claiming another.
func TestAFixtureAndATargetIsAUsageError(t *testing.T) {
	t.Parallel()
	code, _, errOut := run(t, failIfItReachesAzure(t),
		"check", "--fixture", "../replay/scenarios/disk-yes-unattached", testTarget)
	if code != 2 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(errOut, "names its own target") {
		t.Errorf("the error does not say what was wrong: %q", errOut)
	}
}

func TestAMissingFixtureDirectoryIsAUsageError(t *testing.T) {
	t.Parallel()
	code, _, errOut := run(t, failIfItReachesAzure(t), "check", "--fixture", t.TempDir(), "-o", "json")
	if code != 2 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(errOut, ManifestNameForTest) {
		t.Errorf("the error does not name what was missing: %q", errOut)
	}
}

// ManifestNameForTest keeps the expectation above next to the layout it is about.
const ManifestNameForTest = "manifest.yaml"

// A pinned subscription is a statement about which tenant somebody means to
// be looking at. A recording of a different one is the mix-up they asked to be
// caught, replay or not.
func TestAReplayHonoursThePinnedSubscription(t *testing.T) {
	t.Parallel()
	const dir = "../replay/scenarios/disk-yes-unattached"
	fixture, err := replay.Scenario("disk-yes-unattached")
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, failIfItReachesAzure(t), "check", "--fixture", dir,
		"--subscription", "99999999-9999-9999-9999-999999999999"); code != 2 {
		t.Fatalf("a foreign subscription was accepted: code=%d stderr=%q", code, errOut)
	}
	if code, _, errOut := run(t, failIfItReachesAzure(t), "check", "--fixture", dir,
		"--subscription", fixture.Manifest.SubscriptionID, "-o", "json"); code != 0 {
		t.Fatalf("the fixture's own subscription was rejected: code=%d stderr=%q", code, errOut)
	}
}

// SPEC 7.5 names AZCID_RECORD as the path that produces a fixture. It used to
// be absent while the plan said the machinery was finished, which is the
// claim CLAUDE.md forbids. These hold the shape of the command rather than
// its network half: a recording talks to Azure, and no test here may.
func TestRecordingRefusesMoreThanOneTarget(t *testing.T) {
	t.Setenv(RecordEnv, t.TempDir())
	code, _, errOut := run(t, failIfItReachesAzure(t), "check", testTarget, testTarget)
	if code != 2 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(errOut, "recording takes one target") {
		t.Errorf("the error does not say what was wrong: %q", errOut)
	}
}

// A recording directory that cannot be made is a refusal, not a run that
// quietly records nothing.
func TestRecordingRefusesADirectoryItCannotMake(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(RecordEnv, filepath.Join(file, "under-a-file"))
	code, _, errOut := run(t, failIfItReachesAzure(t), "check", testTarget)
	if code == 0 {
		t.Fatalf("a recording that could not be kept reported success: %q", errOut)
	}
}
