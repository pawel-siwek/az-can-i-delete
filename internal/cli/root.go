// Package cli exposes command validation and process exit-code handling.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ExitError associates a command error with its process exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

type outputOptions struct {
	format         string
	onlyShowErrors bool
	debug          bool
	query          string
}

// Run executes an isolated command tree using the supplied streams.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, version string) int {
	root := NewRootCommand(version)
	root.SetArgs(args)
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	if err := root.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(errOut, "error: %s\n", err)
		var exit *ExitError
		if errors.As(err, &exit) {
			return exit.Code
		}
		return 1
	}
	return 0
}

// NewRootCommand creates a command tree without shared flag state.
func NewRootCommand(version string) *cobra.Command {
	options := &outputOptions{}
	root := &cobra.Command{
		Use:           "az-can-i-delete",
		Short:         "Evidence before infrastructure deletion",
		Long:          "Collect deterministic Azure resource evidence before deletion.\nThis initial command scaffold exposes help and version; assessment and mutation commands are not implemented yet.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          usageArgs(cobra.NoArgs),
		RunE:          func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("output") {
				options.format = defaultOutputFormat(cmd.OutOrStdout())
			}
			if err := output.ValidateFormat(options.format); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if cmd.Flags().Changed("query") {
				return &ExitError{Code: 2, Err: errors.New("query is not implemented")}
			}
			return nil
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &ExitError{Code: 2, Err: err}
	})
	root.PersistentFlags().StringVarP(&options.format, "output", "o", defaultOutputFormat(os.Stdout), "Output format (json, jsonc, table, tsv, yaml or none; terminal default table, otherwise json)")
	root.PersistentFlags().BoolVar(&options.onlyShowErrors, "only-show-errors", false, "Suppress non-error diagnostics")
	root.PersistentFlags().BoolVar(&options.debug, "debug", false, "Enable diagnostics without credentials or setting values")
	root.PersistentFlags().StringVar(&options.query, "query", "", "JMESPath query (not implemented)")

	check := unavailableCommand("check [id-or-portal-url ...]", "Assess resource evidence (not implemented)", cobra.ArbitraryArgs)
	var ids []string
	check.Flags().StringArrayVar(&ids, "ids", nil, "Resource IDs or portal URLs (space-delimited or repeated --ids)")
	check.Args = usageArgs(func(cmd *cobra.Command, args []string) error {
		if len(ids)+len(args) == 0 {
			return errors.New("check requires a target or --ids")
		}

		return validateTargets(cmd, append(append([]string(nil), ids...), args...))
	})
	check.Flags().String("window", "30d", "Observation window, 7-93 days")
	check.Flags().Bool("data-plane", false, "Opt in to bounded OAuth-only storage metadata collection")
	check.Flags().String("subscription", "", "Expected subscription ID")
	check.Flags().Bool("exit-on-verdict", false, "Exit by verdict severity: no=10, tentative=11, yes=0")
	check.Flags().String("fixture", "", "Replay recorded responses instead of Azure")
	check.Flags().Bool("redact-tags", false, "Redact tag values")

	cordon := unavailableCommand("cordon <id>", "Start a reversible observation trial (not implemented)", cobra.ExactArgs(1))
	cordon.Flags().Bool("yes", false, "Confirm the CLI operation")
	cordon.Flags().Bool("force", false, "Acknowledge supported explicit preflight overrides")
	cordon.Flags().Bool("dry-run", false, "Show the operation without applying it")
	cordon.Flags().String("window", "7d", "Trial window, 1-30 days")
	uncordon := unavailableCommand("uncordon <id>", "Restore recorded prior state (not implemented)", cobra.ExactArgs(1))
	uncordon.Flags().Bool("yes", false, "Confirm the CLI operation")
	uncordon.Flags().Bool("from-history", false, "Use local recorded state")
	uncordon.Flags().String("prior", "", "Explicit prior state for manual recovery")
	status := unavailableCommand("status <id>", "Inspect trial status (not implemented)", cobra.ExactArgs(1))
	status.Flags().Bool("from-history", false, "Use local recorded state")
	for _, command := range []*cobra.Command{cordon, uncordon, status} {
		command.Flags().String("subscription", "", "Expected subscription ID")
		command.Args = usageArgs(func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			return validateTargets(cmd, args)
		})
	}
	history := unavailableCommand("history", "Inspect local operation history (not implemented)", cobra.NoArgs)
	demo := unavailableCommand("demo <scenario>", "Run a labelled recorded fixture (not implemented)", cobra.ExactArgs(1))
	patterns := &cobra.Command{
		Use: "patterns", Short: "Inspect storage knowledge-base patterns",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	patterns.AddCommand(unavailableCommand("list", "List embedded patterns (not implemented)", cobra.NoArgs))
	mcp := unavailableCommand("mcp", "Serve read-only MCP tools (not implemented)", cobra.NoArgs)
	mcp.Flags().Bool("redact-tags", true, "Redact tag values in MCP output")
	mcp.Flags().String("fixture", "", "Replay recorded responses instead of Azure")
	versionCommand := &cobra.Command{
		Use: "version", Short: "Print the binary version",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "az-can-i-delete %s\n", version)
			return err
		},
	}
	root.AddCommand(check, cordon, uncordon, status, history, demo, patterns, mcp, versionCommand)
	return root
}

func defaultOutputFormat(out io.Writer) string {
	file, ok := out.(*os.File)
	return formatForTerminal(ok && term.IsTerminal(int(file.Fd())))
}

func formatForTerminal(terminal bool) string {
	if terminal {
		return "table"
	}
	return "json"
}

func validateTargets(cmd *cobra.Command, inputs []string) error {
	subscription, err := cmd.Flags().GetString("subscription")
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("subscription") && subscription == "" {
		return errors.New("subscription must be a GUID")
	}
	for i, input := range inputs {
		target, err := armid.Parse(input)
		if err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
		}
		if err := target.ValidateSubscription(subscription); err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
		}
	}
	return nil
}

func usageArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			return &ExitError{Code: 2, Err: err}
		}
		return nil
	}
}

func unavailableCommand(use, short string, args cobra.PositionalArgs) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: usageArgs(args),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &ExitError{Code: 1, Err: fmt.Errorf("%s is not implemented yet", cmd.CommandPath())}
		},
	}
}
