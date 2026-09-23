package cli

import (
	"path/filepath"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/mcpserver"
	"github.com/spf13/cobra"
)

// captured runs the mcp command without serving, and returns the server it
// would have started.
func captured(t *testing.T, args ...string) (int, mcpserver.Config, string) {
	t.Helper()
	var got mcpserver.Config
	deps := testDeps(nil, nil)
	deps.Serve = func(_ *cobra.Command, cfg mcpserver.Config) error {
		got = cfg
		return nil
	}
	code, _, errOut := run(t, deps, append([]string{"mcp"}, args...)...)
	return code, got, errOut
}

func TestMCPRedactsTagsUnlessThePersonStartingItSaysOtherwise(t *testing.T) {
	t.Setenv("AZCID_HOME", t.TempDir())
	code, cfg, errOut := captured(t)
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !cfg.RedactTags || cfg.Replay || cfg.Checker == nil || cfg.Status == nil {
		t.Fatalf("config = %+v", cfg)
	}
	if _, cfg, _ = captured(t, "--redact-tags=false"); cfg.RedactTags {
		t.Fatal("--redact-tags=false was ignored")
	}
}

func TestMCPServesARecordingWhenGivenOne(t *testing.T) {
	t.Setenv("AZCID_HOME", t.TempDir())
	dir := filepath.Join("..", "replay", "scenarios", "disk-yes-unattached")
	code, cfg, errOut := captured(t, "--fixture", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !cfg.Replay || cfg.ReplayTime.IsZero() {
		t.Fatalf("config = %+v", cfg)
	}
	if code, _, _ := captured(t, "--fixture", t.TempDir()); code != 2 {
		t.Fatalf("an empty fixture directory: exit %d, want 2", code)
	}
}
