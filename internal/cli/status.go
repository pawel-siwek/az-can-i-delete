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
		return writeStatus(w, target, status)
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
func writeStatus(w io.Writer, target armid.Target, s cordon.Status) error {
	var b strings.Builder
	name := output.Untrusted(target.Name)
	field := "publicNetworkAccess"
	if strings.EqualFold(target.ResourceType, cordon.SiteType) {
		field = "state"
	}
	switch {
	case !s.Cordoned:
		fmt.Fprintf(&b, "   not cordoned — %s (%s %s)\n", name, field, s.CurrentState)
		_, err := io.WriteString(w, b.String())
		return err
	case s.TagCorrupt:
		fmt.Fprintf(&b, "‼  CORDON TAG DAMAGED — %s (%s %s)\n\n", name, field, s.CurrentState)
	case s.Reverted:
		fmt.Fprintf(&b, "‼  REVERTED — %s (%s %s)\n\n", name, field, s.CurrentState)
		if s.RevertedAt != nil {
			fmt.Fprintf(&b, "    last write at %s", s.RevertedAt.Format(time.RFC3339))
			if who := s.Untrusted["revertedBy"]; who != "" {
				fmt.Fprintf(&b, " by %s `%s`", s.Untrusted["revertedByClass"], who)
			}
			b.WriteString("\n\n")
		}
	default:
		fmt.Fprintf(&b, "🧱  CORDONED — %s (%s %s)\n\n", name, field, s.CurrentState)
	}
	if s.Since != nil {
		fmt.Fprintf(&b, "    mode %s since %s by %s · %d h elapsed · %d h left of %d d\n",
			s.Mode, s.Since.Format(time.RFC3339), s.By, *s.ElapsedHours, *s.RemainingHours, s.WindowDays)
		fmt.Fprintf(&b, "    prior %s (from the %s)\n", s.Prior, s.Source)
	}
	for _, slot := range s.Slots {
		fmt.Fprintf(&b, "    slot %s: was %s, now %s\n", slot.Name, slot.Prior, slot.Current)
	}
	if len(s.Activity) > 0 {
		b.WriteString("\n📣  Since the cordon\n")
		for _, counter := range s.Activity {
			fmt.Fprintf(&b, "    %-14s %12.0f  %s\n", counter.Metric, counter.Total, counter.Meaning)
		}
	}
	if len(s.Unknowns) > 0 {
		b.WriteString("\n🚧  Could not read\n")
		for _, unknown := range s.Unknowns {
			fmt.Fprintf(&b, "    %s (%s) — %s\n", unknown.ID, unknown.Code, unknown.Message)
		}
	}
	if s.TagCorrupt {
		fmt.Fprintf(&b, "    raw tag (untrusted): %s\n", s.Untrusted["tag"])
	}
	if len(s.Caveats) > 0 {
		b.WriteString("\n    What this cannot see:\n")
		for _, caveat := range s.Caveats {
			fmt.Fprintf(&b, "    · %s\n", caveat)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
