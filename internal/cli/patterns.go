package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/kb"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/spf13/cobra"
)

// pattern is one knowledge base entry as the list prints it. It carries what a
// reader needs to judge a match — what the name suggests, how strongly, and
// what would confirm it — and leaves out the source links: a list printed to
// a terminal is not where a reference is followed, and the embedded kb.yaml
// carries them.
type pattern struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Regex           string   `json:"regex,omitempty"`
	Mechanism       bool     `json:"mechanism"`
	Producer        string   `json:"producer"`
	UnconfirmedTier string   `json:"unconfirmedTier"`
	Tier            string   `json:"tier"`
	Confirm         string   `json:"confirm"`
	Examples        []string `json:"examples,omitempty"`
}

func patternsCommand(options *outputOptions) *cobra.Command {
	patterns := &cobra.Command{
		Use: "patterns", Short: "Inspect storage knowledge-base patterns",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the embedded name patterns, in the order they are matched",
		Long: "List the knowledge base that recognizes a container, share, queue, table, account,\n" +
			"resource group, tag or lock name as the work of a known producer. A name alone is\n" +
			"reported at the unconfirmed tier; the confirmed tier needs the producer found in\n" +
			"configuration. The first matching entry wins, so the order printed is the order used.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := kb.Entries()
			if err != nil {
				return &ExitError{Code: 1, Err: err}
			}
			rows := make([]any, 0, len(entries))
			for _, entry := range entries {
				row := pattern{
					ID: entry.ID, Kind: entry.Kind, Mechanism: entry.Mechanism, Producer: entry.Producer,
					UnconfirmedTier: entry.UnconfirmedTier, Tier: entry.Tier, Confirm: entry.Confirm, Examples: entry.Examples,
				}
				if !entry.Mechanism {
					row.Regex = entry.Regex
				}
				rows = append(rows, row)
			}
			document := map[string]any{"rulesDate": kb.Date(), "count": len(rows), "patterns": rows}
			return output.RenderValues(cmd.OutOrStdout(), options.format, []any{document}, func(w io.Writer) error {
				return writePatterns(w, entries)
			})
		},
	}
	patterns.AddCommand(list)
	return patterns
}

func writePatterns(w io.Writer, entries []kb.Entry) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%d patterns · rules %s · first match wins\n\n", len(entries), kb.Date())
	kind := ""
	for _, entry := range entries {
		if entry.Kind != kind {
			kind = entry.Kind
			fmt.Fprintf(&b, "%s\n", kind)
		}
		match := entry.Regex
		if entry.Mechanism {
			match = "(confirmed by configuration, never by name)"
		}
		fmt.Fprintf(&b, "  %-38s %s → %s\n", entry.ID, entry.UnconfirmedTier, entry.Tier)
		fmt.Fprintf(&b, "  %-38s %s\n", "", match)
		fmt.Fprintf(&b, "  %-38s %s\n", "", entry.Producer)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
