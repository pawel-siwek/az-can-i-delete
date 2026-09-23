package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/azure"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/replay"
	"github.com/spf13/cobra"
)

// replayRunner assesses from a recording. It builds no credential and opens no
// connection: a demonstration must work on a laptop that has never signed in,
// and a recording that quietly reached Azure would not be a recording.
func replayRunner(version string, fixture *replay.Fixture) (*assess.Runner, error) {
	client, err := azure.Recorded(fixture.Transport(), version)
	if err != nil {
		return nil, err
	}
	return assess.New(collect.Clients{
		ARM: client.ARM(), Graph: client.Graph(),
		Metrics: client.Metrics(), ActivityLog: client.ActivityLog(),
	}, version), nil
}

// runReplay assesses the fixture's target and prints it, labelled.
//
// The cutoff comes from the recording rather than from the clock. Decide() is
// a function of its inputs (ADR-0003), so a recording made a year ago reaches
// the same verdict today — which is the only reason a recorded demonstration
// is worth showing.
func runReplay(cmd *cobra.Command, version string, options *outputOptions, fixture *replay.Fixture) error {
	target, err := armid.Parse(fixture.Manifest.ResourceID)
	if err != nil {
		return &ExitError{Code: 1, Err: fmt.Errorf("the fixture's resourceId is not a resource id: %w", err)}
	}
	// The guard applies to a replay like any other run. Somebody who pins a
	// subscription is saying which one they mean to be looking at, and a
	// recording of a different one is exactly the mix-up they asked to catch.
	if err := target.ValidateSubscription(subscriptionFlag(cmd)); err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	window := fixture.Manifest.Window
	if window == "" {
		window = defaultWindow
	}
	requested, err := assess.ParseWindow(window, fixture.Manifest.Now)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	runner, err := replayRunner(version, fixture)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	writeBanner(cmd, fixture, options)

	outcome, checkErr := runner.Check(cmd.Context(), target, assess.Options{
		Requested: requested, Cutoff: fixture.Manifest.Now, Replay: true,
	})
	if checkErr != nil {
		// A fixture miss lands here. It is a broken recording, not a verdict,
		// and it must never be reported as one.
		return &ExitError{Code: 1, Err: checkErr}
	}
	var view []output.ViewOption
	if full, flagErr := cmd.Flags().GetBool("full"); flagErr == nil && full {
		view = append(view, output.Detailed())
	}
	if err := output.Render(cmd.OutOrStdout(), options.format, []output.Outcome{outcome}, view...); err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

// writeBanner names the recording before its verdict appears.
//
// The report already says it is a replay, in every format, so this does not
// repeat that. What it adds is which recording and from when — the two things
// a reader needs to judge what they are looking at, and the two the report
// cannot know.
func writeBanner(cmd *cobra.Command, fixture *replay.Fixture, options *outputOptions) {
	if options.onlyShowErrors || !output.IsHuman(options.format) {
		return
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "\n📼  %s · recorded %s\n", fixture.Name, fixture.Manifest.Now.Format("2006-01-02"))
	if title := fixture.Manifest.Title; title != "" {
		writeWrapped(out, "    ", fixture.Manifest.Title)
	}
}

// writeWrapped keeps a title inside a terminal without hyphenating anything.
func writeWrapped(out io.Writer, indent, text string) {
	const width = 96
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && line != indent {
			_, _ = fmt.Fprintln(out, line)
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += word
	}
	if line != indent {
		_, _ = fmt.Fprintln(out, line)
	}
}

// subscriptionFlag reads --subscription where the command has one; `demo`
// does not, and an absent flag pins nothing.
func subscriptionFlag(cmd *cobra.Command) string {
	if cmd.Flags().Lookup("subscription") == nil {
		return ""
	}
	value, err := cmd.Flags().GetString("subscription")
	if err != nil {
		return ""
	}
	return value
}

// listScenarios prints what `demo` can show.
func listScenarios(cmd *cobra.Command) error {
	slugs := replay.Scenarios()
	if len(slugs) == 0 {
		return &ExitError{Code: 1, Err: errors.New("this binary carries no recorded scenarios")}
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Recorded scenarios, replayed through the real collectors and rules:\n\n")
	for _, slug := range slugs {
		fixture, err := replay.Scenario(slug)
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(out, "  %-32s %s\n", slug, verdictWord(fixture.Manifest.Expect.Verdict))
		if title := fixture.Manifest.Title; title != "" {
			_, _ = fmt.Fprintf(out, "  %-32s %s\n", "", title)
		}
	}
	_, _ = fmt.Fprintf(out, "\n  %s demo <scenario>\n", cmd.Root().Name())
	return nil
}

func verdictWord(verdict string) string {
	switch strings.ToLower(verdict) {
	case "yes":
		return "✅ yes"
	case "no":
		return "⛔ no"
	case "tentative":
		return "⚠️  tentative"
	default:
		return verdict
	}
}
