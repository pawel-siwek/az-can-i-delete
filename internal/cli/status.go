package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/spf13/cobra"
)

func statusCommand(deps Dependencies, version string, options *outputOptions) *cobra.Command {
	status := &cobra.Command{
		Use:   "status <id>",
		Short: "Show a cordon and what has reached the resource since",
		Long: "Read the azcid tag, the state the resource is in now, and the traffic since the cordon\n" +
			"started. It reads; it never writes. Denied requests may not be recorded, and private\n" +
			"endpoints and trusted Azure services are not blocked by a cordon.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, deps, version, options, args[0])
		},
	}
	status.Flags().Bool("from-history", false, "Use the local history file when the azcid tag is gone")
	return status
}

func runStatus(cmd *cobra.Command, deps Dependencies, version string, options *outputOptions, input string) error {
	target, err := armid.Parse(input)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	if _, refusal := cordon.Gate(target.ResourceType); refusal != nil {
		return &ExitError{Code: refusal.Exit, Err: refusal}
	}
	fromHistory, err := cmd.Flags().GetBool("from-history")
	if err != nil {
		return err
	}
	history, err := cordon.DefaultHistory()
	if err != nil && fromHistory {
		return &ExitError{Code: 1, Err: err}
	}
	runner, err := deps.Runner(version, false)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	reader := cordon.Reader{ARM: runner.Clients.ARM, Metrics: runner.Clients.Metrics, ActivityLog: runner.Clients.ActivityLog}
	status, err := reader.Status(cmd.Context(), target, cordon.StatusOptions{
		Now: deps.Now().UTC(), History: history, FromHistory: fromHistory,
	})
	if err != nil {
		return statusError(err)
	}
	return output.RenderValues(cmd.OutOrStdout(), options.format, []any{status}, func(w io.Writer) error {
		return writeStatus(w, output.NewPalette(options.color), target, status)
	})
}

func statusError(err error) error {
	var refusal *cordon.Refusal
	switch {
	case errors.As(err, &refusal):
		return &ExitError{Code: refusal.Exit, Err: refusal}
	case errors.Is(err, cordon.ErrNotFound):
		return &ExitError{Code: 3, Err: err}
	}
	return &ExitError{Code: 1, Err: err}
}

// writeStatus is the human view: the state first, then the screams, then what
// the cordon cannot hear.
func writeStatus(w io.Writer, p output.Palette, target armid.Target, s cordon.Status) error {
	var b strings.Builder
	field := "publicNetworkAccess"
	if strings.EqualFold(target.ResourceType, cordon.SiteType) {
		field = "state"
	}
	branch := p.Dim("⎿")
	switch {
	case !s.Cordoned:
		fmt.Fprintf(&b, "\n  %s  %s\n  %s  %s\n", p.Pill("", "not cordoned"), p.Bold(field+" "+s.CurrentState), branch, p.Dim(target.ID))
		_, err := io.WriteString(w, b.String())
		return err
	case s.TagCorrupt:
		fmt.Fprintf(&b, "\n  %s  %s\n", p.Pill("no", "‼ CORDON TAG DAMAGED"), p.Bold(field+" "+s.CurrentState))
	case s.Reverted:
		fmt.Fprintf(&b, "\n  %s  %s\n", p.Pill("no", "‼ REVERTED"), p.Bold(field+" "+s.CurrentState))
	default:
		label := "🧱 CORDONED"
		if s.ElapsedHours != nil {
			label = fmt.Sprintf("🧱 CORDONED %d h of %d d", *s.ElapsedHours, s.WindowDays)
		}
		fmt.Fprintf(&b, "\n  %s  %s\n", p.Pill("cordon", label), p.Bold(field+" "+s.CurrentState))
	}
	// The canonical id, never the name on its own: the name is somebody's
	// text, and the id is the one form of it this tool has parsed.
	fmt.Fprintf(&b, "  %s  %s\n", branch, p.Dim(target.ID))
	if s.Reverted && s.RevertedAt != nil {
		fmt.Fprintf(&b, "  %s  %s\n", branch, p.Red(fmt.Sprintf("last write at %s by a %s", s.RevertedAt.Format(time.RFC3339), s.Untrusted["revertedByClass"])))
	}
	if s.Since != nil {
		fmt.Fprintf(&b, "  %s  mode %s since %s by %s · %d h elapsed · %d h left of %d d\n",
			branch, s.Mode, s.Since.Format(time.RFC3339), s.By, *s.ElapsedHours, *s.RemainingHours, s.WindowDays)
		fmt.Fprintf(&b, "  %s  %s\n", branch, p.Dim(fmt.Sprintf("prior %s (from the %s)", s.Prior, s.Source)))
	}
	for _, slot := range s.Slots {
		fmt.Fprintf(&b, "  %s  %s: was %s, now %s\n", branch, slot.Ref, slot.Prior, slot.Current)
	}
	if len(s.Activity) > 0 {
		fmt.Fprintf(&b, "\n  📣 %s\n", p.Amber("Since the cordon"))
		for _, counter := range s.Activity {
			fmt.Fprintf(&b, "     %-14s %12.0f  %s\n", counter.Metric, counter.Total, p.Dim(counter.Meaning))
		}
	}
	if len(s.Unknowns) > 0 {
		fmt.Fprintf(&b, "\n  🟡 %s\n", p.Amber("Could not read"))
		for _, unknown := range s.Unknowns {
			fmt.Fprintf(&b, "  %s %s %s %s\n", p.Amber("?"), p.Bold(unknown.ID), p.Dim("("+string(unknown.Code)+")"), p.Dim("— "+unknown.Message))
		}
	}
	// Azure's own text is never part of a sentence this tool says. It is
	// printed on its own, labelled as what it is.
	if len(s.Untrusted) > 0 {
		fmt.Fprintf(&b, "\n  %s\n", p.Dim("untrusted (Azure metadata; may contain anybody's text):"))
		keys := []string{"revertedBy", "tag"}
		for _, slot := range s.Slots {
			keys = append(keys, slot.Ref)
		}
		for _, key := range keys {
			if value := s.Untrusted[key]; value != "" {
				fmt.Fprintf(&b, "    %s: %s\n", key, value)
			}
		}
	}
	if len(s.Caveats) > 0 {
		fmt.Fprintf(&b, "\n  %s\n", p.Dim("What this cannot see:"))
		for _, caveat := range s.Caveats {
			fmt.Fprintf(&b, "  %s  %s\n", branch, p.Dim(caveat))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
