// Package cli exposes command validation and process exit-code handling.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ExitError associates a command error with its process exit code.
type ExitError struct {
	Code int
	Err  error
}

// Error keeps a silent exit printable for callers that log it; a nil error
// means the exit code carries the whole message, as with --exit-on-verdict.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}
func (e *ExitError) Unwrap() error { return e.Err }

// defaultWindow is the observation window a run uses when nobody chose one.
const defaultWindow = "30d"

type outputOptions struct {
	format         string
	onlyShowErrors bool
	debug          bool
	query          string
}

// Dependencies are the process-level effects the command tree needs. Tests
// replace them so no test can reach Azure or read the real clock.
type Dependencies struct {
	// Now supplies the observation cutoff. Everything below the CLI takes the
	// cutoff as an input; nothing reads a clock of its own.
	Now func() time.Time
	// Runner builds the assessment runner, which is where credentials and
	// network access enter the process.
	Runner func(version string, dataPlane bool) (*assess.Runner, error)
	// Serve runs the MCP server. Nil serves stdio.
	Serve Serve
}

// DefaultDependencies talk to Azure with the credential chain.
func DefaultDependencies() Dependencies {
	return Dependencies{Now: time.Now, Runner: azureRunner}
}

func azureRunner(version string, dataPlane bool) (*assess.Runner, error) {
	client, err := azure.New(azure.Options{ToolVersion: version})
	if err != nil {
		return nil, err
	}
	clients := collect.Clients{
		ARM:         client.ARM(),
		Graph:       client.Graph(),
		Metrics:     client.Metrics(),
		ActivityLog: client.ActivityLog(),
	}
	// The storage data plane needs its own token, so it is built only when
	// the caller asked for it: an ordinary run never requests that scope.
	if dataPlane {
		plane, err := azure.DataPlane(azure.DataPlaneOptions{ToolVersion: version})
		if err != nil {
			return nil, err
		}
		clients.DataPlane = plane
	}
	return assess.New(clients, version), nil
}

// Run executes an isolated command tree using the supplied streams.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, version string) int {
	return RunWith(ctx, args, in, out, errOut, version, DefaultDependencies())
}

// RunWith executes the command tree over explicit dependencies. Tests use it
// to run the real command paths without credentials or network access.
func RunWith(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, version string, deps Dependencies) int {
	root := NewRootCommandWith(version, deps)
	root.SetArgs(args)
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	if err := root.ExecuteContext(ctx); err != nil {
		var exit *ExitError
		if errors.As(err, &exit) {
			// A verdict the caller asked to exit on is not an error, so it
			// carries a code without a message.
			if exit.Err != nil {
				_, _ = fmt.Fprintf(errOut, "error: %s\n", exit.Err)
			}
			return exit.Code
		}
		_, _ = fmt.Fprintf(errOut, "error: %s\n", err)
		return 1
	}
	return 0
}

// NewRootCommand creates a command tree without shared flag state.
func NewRootCommand(version string) *cobra.Command {
	return NewRootCommandWith(version, DefaultDependencies())
}

// NewRootCommandWith creates the command tree over explicit dependencies.
func NewRootCommandWith(version string, deps Dependencies) *cobra.Command {
	options := &outputOptions{}
	root := &cobra.Command{
		Use:   "az-can-i-delete",
		Short: "Evidence before infrastructure deletion",
		Long: "Collect deterministic Azure resource evidence before deletion.\n\n" +
			"`check` assesses storage accounts, managed disks, network interfaces, public IP\n" +
			"addresses, network security groups, virtual machines, App Service sites and plans.\n" +
			"It reads; it never writes. The commands marked not implemented say so and exit 1.\n\n" +
			"A verdict is evidence, not permission.",
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

	var ids []string
	check := &cobra.Command{
		Use:   "check [id-or-portal-url ...]",
		Short: "Assess the evidence for one or more resources",
		Long: "Collect the evidence for each target and print a verdict with the signals it rests on.\n" +
			"A verdict is evidence, not permission: `yes` means no evidence of use was found by the\n" +
			"signals this tool could evaluate, never that deleting is safe.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd, deps, version, options, append(append([]string(nil), ids...), args...))
		},
	}
	check.Flags().StringArrayVar(&ids, "ids", nil, "Resource IDs or portal URLs (space-delimited or repeated --ids)")
	check.Args = usageArgs(func(cmd *cobra.Command, args []string) error {
		// A replay names its own target: the recording says what it is of, so
		// asking for one again is a chance to point it at the wrong resource.
		if fixture, err := cmd.Flags().GetString("fixture"); err == nil && fixture != "" {
			if len(ids)+len(args) > 0 {
				return errors.New("a fixture names its own target; pass --fixture or a target, not both")
			}
			return nil
		}
		if len(ids)+len(args) == 0 {
			return errors.New("check requires a target or --ids")
		}

		return validateTargets(cmd, append(append([]string(nil), ids...), args...))
	})
	check.Flags().String("window", defaultWindow, "Observation window, 7-93 days")
	check.Flags().Bool("data-plane", false, "Opt in to bounded OAuth-only storage metadata collection")
	check.Flags().Bool("full", false, "Print every signal and the limitations, not just what was found")
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
	status := statusCommand(deps, version, options)
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
	demo := &cobra.Command{
		Use:   "demo [scenario]",
		Short: "Replay a recorded scenario through the real collectors and rules",
		Long: "Run one of the recordings shipped in this binary. No credential is used and no\n" +
			"connection is opened: the collectors, the analyzers and the verdict rules are the\n" +
			"real ones, and only the answers Azure gave are recorded.\n\n" +
			"A recording is not an observation. Every replayed report says so.",
		Args: usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return listScenarios(cmd)
			}
			fixture, err := replay.Scenario(args[0])
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			return runReplay(cmd, version, options, fixture)
		},
	}
	demo.Flags().Bool("full", false, "Print every signal and the limitations, not just what was found")
	patterns := patternsCommand(options)
	mcp := mcpCommand(deps, version)
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

// runCheck assesses every target and reduces the outcomes to one exit code.
// An error never becomes evidence: a target that could not be assessed is
// reported on the error stream and as a failed outcome, and the completed
// assessments are still printed.
func runCheck(cmd *cobra.Command, deps Dependencies, version string, options *outputOptions, inputs []string) error {
	if dir, err := cmd.Flags().GetString("fixture"); err == nil && dir != "" {
		fixture, openErr := replay.Open(dir)
		if openErr != nil {
			return &ExitError{Code: 2, Err: openErr}
		}
		return runReplay(cmd, version, options, fixture)
	}
	cutoff := assess.Cutoff(deps.Now())
	window, err := cmd.Flags().GetString("window")
	if err != nil {
		return err
	}
	requested, err := assess.ParseWindow(window, cutoff)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	redactTags, err := cmd.Flags().GetBool("redact-tags")
	if err != nil {
		return err
	}
	exitOnVerdict, err := cmd.Flags().GetBool("exit-on-verdict")
	if err != nil {
		return err
	}
	targets := make([]armid.Target, 0, len(inputs))
	for _, input := range inputs {
		target, parseErr := armid.Parse(input)
		if parseErr != nil {
			return &ExitError{Code: 2, Err: parseErr}
		}
		targets = append(targets, target)
	}
	dataPlane, err := cmd.Flags().GetBool("data-plane")
	if err != nil {
		return err
	}

	// SPEC 7.5: the recording path is the ordinary check with a directory to
	// keep the answers in.
	if dir := os.Getenv(RecordEnv); dir != "" {
		return runRecord(cmd, version, options, dir, targets, cutoff, requested, redactTags)
	}

	runner, err := deps.Runner(version, dataPlane)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	outcomes := make([]output.Outcome, 0, len(targets))
	var failures []error
	for _, target := range targets {
		outcome, checkErr := runner.Check(cmd.Context(), target, assess.Options{
			Requested: requested, Cutoff: cutoff, RedactTags: redactTags, DataPlane: dataPlane,
		})
		outcomes = append(outcomes, outcome)
		if checkErr != nil {
			failures = append(failures, checkErr)
		}
	}
	// The terminal view shows what was found; --full restores everything.
	var view []output.ViewOption
	if full, flagErr := cmd.Flags().GetBool("full"); flagErr == nil && full {
		view = append(view, output.Detailed())
	}
	if err := output.Render(cmd.OutOrStdout(), options.format, outcomes, view...); err != nil && len(failures) == 0 {
		return &ExitError{Code: 1, Err: err}
	}
	code := output.ExitCode(outcomes, exitOnVerdict)
	if len(failures) > 0 {
		return &ExitError{Code: code, Err: errors.Join(failures...)}
	}
	if code != 0 {
		return &ExitError{Code: code, Err: exitReason(outcomes)}
	}
	return nil
}

// exitReason explains a non-zero exit that no error accompanied. A verdict the
// caller asked to exit on is a result, not a failure, so it has no message.
func exitReason(outcomes []output.Outcome) error {
	switch output.ExitCode(outcomes, false) {
	case 3:
		return errors.New("the resource was not found")
	case 4:
		return errors.New("no signals were evaluable")
	case 0:
		return nil
	default:
		return errors.New("the assessment did not complete")
	}
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
