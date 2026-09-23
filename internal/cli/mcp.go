package cli

import (
	"errors"

	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
	"github.com/pawel-siwek/az-can-i-delete/internal/mcpserver"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
	"github.com/spf13/cobra"
)

// Serve runs an MCP server; tests replace it so no test holds stdio open.
type Serve func(cmd *cobra.Command, cfg mcpserver.Config) error

func serveStdio(cmd *cobra.Command, cfg mcpserver.Config) error {
	return mcpserver.Serve(cmd.Context(), cfg)
}

func mcpCommand(deps Dependencies, version string) *cobra.Command {
	command := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the read-only MCP tools can_i_delete and cordon_status over stdio",
		Long: "Serve two tools to an MCP client over stdin and stdout: can_i_delete, which returns the\n" +
			"same report as check, and cordon_status, which returns the same state as status. Neither\n" +
			"changes Azure state, and no tool that does is registered. Tag values are redacted unless\n" +
			"--redact-tags=false is given here; nothing a client sends can change that.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := mcpConfig(cmd, deps, version)
			if err != nil {
				return err
			}
			serve := deps.Serve
			if serve == nil {
				serve = serveStdio
			}
			if err := serve(cmd, cfg); err != nil {
				return &ExitError{Code: 1, Err: err}
			}
			return nil
		},
	}
	command.Flags().Bool("redact-tags", true, "Redact tag values in MCP output")
	command.Flags().String("fixture", "", "Replay recorded responses instead of Azure")
	return command
}

func mcpConfig(cmd *cobra.Command, deps Dependencies, version string) (mcpserver.Config, error) {
	redact, err := cmd.Flags().GetBool("redact-tags")
	if err != nil {
		return mcpserver.Config{}, err
	}
	history, err := cordon.DefaultHistory()
	if err != nil {
		// No home directory is no history, which cordon_status reports as
		// uncordoned for a resource without a tag. It is not a reason to
		// refuse to serve.
		history = cordon.History{}
	}
	cfg := mcpserver.Config{Version: version, Now: deps.Now, RedactTags: redact, History: history}

	var runner *assess.Runner
	if dir, _ := cmd.Flags().GetString("fixture"); dir != "" {
		fixture, openErr := replay.Open(dir)
		if openErr != nil {
			return mcpserver.Config{}, &ExitError{Code: 2, Err: openErr}
		}
		runner, err = replayRunner(version, fixture)
		cfg.Replay, cfg.ReplayTime = true, fixture.Manifest.Now
	} else {
		runner, err = deps.Runner(version, false)
	}
	if err != nil {
		return mcpserver.Config{}, &ExitError{Code: 1, Err: err}
	}
	if runner == nil {
		return mcpserver.Config{}, &ExitError{Code: 1, Err: errors.New("no assessment runner")}
	}
	cfg.Checker = runner
	cfg.Status = cordon.Reader{ARM: runner.Clients.ARM, Metrics: runner.Clients.Metrics, ActivityLog: runner.Clients.ActivityLog}
	return cfg, nil
}
