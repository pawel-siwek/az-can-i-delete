package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/spf13/cobra"
)

// azureWriter builds the cordon's write boundary. It is its own dependency,
// separate from Runner, so the check path never holds one.
func azureWriter(version string) (cordon.Writer, error) {
	client, err := azure.New(azure.Options{ToolVersion: version})
	if err != nil {
		return nil, err
	}
	return client.Writer(collect.SystemClock()), nil
}

func cordonCommand(deps Dependencies, version string, options *outputOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "cordon <id>",
		Short: "Start a reversible scream test: storage public access off, or a site stopped",
		Long: "Isolate a storage account (publicNetworkAccess Disabled) or stop an App Service site and\n" +
			"its slots, record the prior state in an azcid tag, and verify both. It deletes nothing\n" +
			"and is undone with uncordon. It runs check first and refuses a `no` unless --force.\n\n" +
			"A cordon does not block private endpoints, resource-instance rules or trusted Azure\n" +
			"services, and denied requests may not appear in metrics.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCordon(cmd, deps, version, options, args[0])
		},
	}
	command.Flags().Bool("yes", false, "Confirm the plan, and every warning that asks for it")
	command.Flags().Bool("force", false, "Cordon despite a `no` verdict or an unreadable policy or lock pre-flight")
	command.Flags().Bool("dry-run", false, "Print the plan and change nothing")
	command.Flags().String("window", fmt.Sprintf("%dd", cordon.DefaultWindowDays), "Cordon window, 1-30 days")
	return command
}

func uncordonCommand(deps Dependencies, version string, options *outputOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "uncordon <id>",
		Short: "Restore the state a cordon recorded, verify it, then remove the tag (needs --yes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUncordon(cmd, deps, version, options, args[0])
		},
	}
	command.Flags().Bool("yes", false, "Confirm the restore; without it nothing is written")
	command.Flags().Bool("from-history", false, "Restore from the local history file when the tag is gone")
	command.Flags().String("prior", "", "Restore an explicit prior state (Enabled, SecuredByPerimeter or Running)")
	return command
}

// cordoner wires the cordon to Azure: the assessment runner for its reads and
// check, and the writer for its writes.
func cordoner(deps Dependencies, version string) (cordon.Cordoner, error) {
	runner, err := deps.Runner(version, false)
	if err != nil {
		return cordon.Cordoner{}, &ExitError{Code: 1, Err: err}
	}
	writerFor := deps.Writer
	if writerFor == nil {
		writerFor = azureWriter
	}
	writer, err := writerFor(version)
	if err != nil {
		return cordon.Cordoner{}, &ExitError{Code: 1, Err: err}
	}
	history, err := cordon.DefaultHistory()
	if err != nil {
		return cordon.Cordoner{}, &ExitError{Code: 1, Err: err}
	}
	now := deps.Now
	return cordon.Cordoner{
		Reader: cordon.Reader{ARM: runner.Clients.ARM, Metrics: runner.Clients.Metrics, ActivityLog: runner.Clients.ActivityLog},
		Writer: writer, History: history, Now: now,
		Assess: func(ctx context.Context, target armid.Target, days int) (map[string]any, error) {
			cutoff := assess.Cutoff(now())
			requested, err := assess.ParseWindow(fmt.Sprintf("%dd", days), cutoff)
			if err != nil {
				return nil, err
			}
			outcome, err := runner.Check(ctx, target, assess.Options{Requested: requested, Cutoff: cutoff})
			if err != nil {
				return nil, err
			}
			switch output.ExitCode([]output.Outcome{outcome}, false) {
			case 0:
			case 3:
				return nil, cordon.ErrNotFound
			default:
				return nil, errors.New("the check before the cordon did not complete")
			}
			return outcome.Value()
		},
	}, nil
}

// cordonReport is what -o json prints for a cordon.
type cordonReport struct {
	ResourceID string `json:"resourceId"`
	Mode       string `json:"mode"`
	Applied    bool   `json:"applied"`
	DryRun     bool   `json:"dryRun"`
	Prior      string `json:"prior"`
	// Untrusted holds the tag this cordon writes. It is rendered by this
	// tool, but a site's tag carries slot names, which are somebody's text.
	Untrusted    map[string]string `json:"untrusted"`
	Verdict      string            `json:"verdict"`
	ReasonClass  string            `json:"reasonClass"`
	Forced       []string          `json:"forced"`
	Consumers    []string          `json:"consumers"`
	Acknowledged []string          `json:"acknowledged"`
	Notes        []string          `json:"notes"`
	NotBlocked   string            `json:"notBlocked"`
	Uncordon     string            `json:"uncordon,omitempty"`
	Status       string            `json:"status,omitempty"`
}

func runCordon(cmd *cobra.Command, deps Dependencies, version string, options *outputOptions, input string) error {
	target, err := armid.Parse(input)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	window, _ := cmd.Flags().GetString("window")
	days, err := cordonWindow(window)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	yes, _ := cmd.Flags().GetBool("yes")
	force, _ := cmd.Flags().GetBool("force")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	c, err := cordoner(deps, version)
	if err != nil {
		return err
	}
	plan, err := c.Preflight(cmd.Context(), target, cordon.Options{WindowDays: days, Force: force, Yes: yes, DryRun: dryRun})
	// A plan waiting for --yes is still printed; every other refusal is not.
	var refusal *cordon.Refusal
	awaiting := errors.As(err, &refusal) && refusal.Code == cordon.CodeConfirmation
	if err != nil && !awaiting {
		return cordonError(err)
	}
	report := planReport(plan)
	if dryRun || err != nil {
		// A dry run, or a plan waiting for --yes: shown in full, nothing written.
		report.DryRun = true
		if renderErr := renderCordon(cmd, options, report); renderErr != nil {
			return &ExitError{Code: 1, Err: renderErr}
		}
		if err != nil {
			return cordonError(err)
		}
		return nil
	}
	applied, err := c.Apply(cmd.Context(), plan)
	if err != nil {
		return cordonError(err)
	}
	report.Applied, report.Uncordon, report.Status = true, applied.Uncordon, "az-can-i-delete status "+target.ID
	if err := renderCordon(cmd, options, report); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

func cordonWindow(flag string) (int, error) {
	var days int
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(flag)), "d")
	if _, err := fmt.Sscanf(trimmed, "%d", &days); err != nil || fmt.Sprint(days) != trimmed {
		return 0, errors.New("window must be a number of days, such as 7d")
	}
	if days < cordon.MinWindowDays || days > cordon.MaxWindowDays {
		return 0, fmt.Errorf("window must be between %dd and %dd", cordon.MinWindowDays, cordon.MaxWindowDays)
	}
	return days, nil
}

func planReport(plan cordon.Plan) cordonReport {
	orEmpty := func(values []string) []string {
		if values == nil {
			return []string{}
		}
		return values
	}
	return cordonReport{
		ResourceID: plan.Target.ID, Mode: string(plan.Mode), Prior: plan.State.Prior, Untrusted: map[string]string{"tag": output.Untrusted(plan.Tag)},
		Verdict: plan.Verdict, ReasonClass: plan.ReasonClass, Forced: orEmpty(plan.Forced),
		Consumers: orEmpty(plan.Consumers), Acknowledged: orEmpty(plan.Acknowledged), Notes: orEmpty(plan.Notes),
		NotBlocked: plan.NotBlocked,
	}
}

func renderCordon(cmd *cobra.Command, options *outputOptions, report cordonReport) error {
	return output.RenderValues(cmd.OutOrStdout(), options.format, []any{report}, func(w io.Writer) error {
		var b strings.Builder
		change := "publicNetworkAccess " + report.Prior + " → Disabled"
		if report.Mode == string(cordon.ModeStop) {
			change = "stop the site and every slot"
		}
		switch {
		case report.Applied:
			fmt.Fprintf(&b, "🧱  CORDONED (%s)\n", change)
		default:
			fmt.Fprintf(&b, "🧱  CORDON PLAN (%s)\n", change)
		}
		// The canonical id on its own line, never the name in a sentence.
		fmt.Fprintf(&b, "    resource %s\n\n", report.ResourceID)
		fmt.Fprintf(&b, "    verdict %s (%s) · a cordon is a test, not permission to delete\n", report.Verdict, report.ReasonClass)
		writeList(&b, "overridden by --force", report.Forced)
		writeList(&b, "might scream", report.Consumers)
		writeList(&b, "acknowledged with --yes", report.Acknowledged)
		for _, note := range report.Notes {
			fmt.Fprintf(&b, "    %s\n", note)
		}
		fmt.Fprintf(&b, "    %s\n", report.NotBlocked)
		b.WriteString("    state tag: see below\n")
		if report.Applied {
			fmt.Fprintf(&b, "\n    watch:  %s\n    undo:   %s\n", report.Status, report.Uncordon)
		} else {
			b.WriteString("\n    nothing was written\n")
		}
		fmt.Fprintf(&b, "\n    untrusted (may contain Azure names):\n      tag: azcid=%s\n", report.Untrusted["tag"])
		_, err := io.WriteString(w, b.String())
		return err
	})
}

func writeList(b *strings.Builder, title string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "    %s: %s\n", title, strings.Join(values, ", "))
}

func cordonError(err error) error {
	var refusal *cordon.Refusal
	switch {
	case errors.As(err, &refusal):
		return &ExitError{Code: refusal.Exit, Err: refusal}
	case errors.Is(err, cordon.ErrNotFound):
		return &ExitError{Code: 3, Err: err}
	}
	return &ExitError{Code: 1, Err: err}
}

// uncordonReport is what -o json prints for an uncordon.
type uncordonReport struct {
	ResourceID string   `json:"resourceId"`
	Mode       string   `json:"mode"`
	Restored   string   `json:"restored"`
	Source     string   `json:"source"`
	TagKept    bool     `json:"tagKept"`
	Notes      []string `json:"notes"`
}

func runUncordon(cmd *cobra.Command, deps Dependencies, version string, options *outputOptions, input string) error {
	target, err := armid.Parse(input)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	if _, refusal := cordon.Gate(target.ResourceType); refusal != nil {
		return &ExitError{Code: refusal.Exit, Err: refusal}
	}
	yes, _ := cmd.Flags().GetBool("yes")
	fromHistory, _ := cmd.Flags().GetBool("from-history")
	prior, _ := cmd.Flags().GetString("prior")
	if fromHistory && prior != "" {
		return &ExitError{Code: 2, Err: errors.New("pass --from-history or --prior, not both")}
	}
	c, err := cordoner(deps, version)
	if err != nil {
		return err
	}
	restored, err := c.Uncordon(cmd.Context(), target, cordon.UncordonOptions{FromHistory: fromHistory, Prior: prior, Yes: yes})
	if err != nil {
		return cordonError(err)
	}
	notes := restored.Notes
	if notes == nil {
		notes = []string{}
	}
	report := uncordonReport{ResourceID: target.ID, Mode: string(restored.State.Mode), Restored: restored.State.Prior,
		Source: restored.Source, TagKept: restored.TagKept, Notes: notes}
	return output.RenderValues(cmd.OutOrStdout(), options.format, []any{report}, func(w io.Writer) error {
		var b strings.Builder
		fmt.Fprintf(&b, "✅  UNCORDONED (restored %s, from the %s)\n    resource %s\n", report.Restored, report.Source, target.ID)
		for _, note := range report.Notes {
			fmt.Fprintf(&b, "    %s\n", note)
		}
		_, err := io.WriteString(w, b.String())
		return err
	})
}
