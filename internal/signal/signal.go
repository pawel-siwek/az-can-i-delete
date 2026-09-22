// Package signal holds what every signal layer shares: the fixed catalogue row
// that decides a signal's tier and criticality, the constructors that turn an
// observation into evidence, and the bounded Resource Graph helper. Keeping
// these in one place is what makes "a failure is never an absence" a property
// of the code rather than a rule each analyzer has to remember.
package signal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Spec is one catalogue row: where a signal comes from, what tier it carries
// and whether an unreadable answer is a critical unknown.
type Spec struct {
	Tier       verdict.Tier
	Critical   bool
	Family     string
	Confidence string
	API        string
	APIVersion string
	// ARGBacked marks a signal that cannot be trusted when the Resource Graph
	// visibility probe did not find the target.
	ARGBacked bool
}

// Catalogue is a signal layer's complete fixed table, keyed by signal ID.
type Catalogue map[string]Spec

// Evidence builds one catalogue-consistent observation. Only the tier, status,
// criticality and typed details come from here; every user-facing string is
// the output policy's, so no Azure text can reach a summary through a signal.
func (c Catalogue) Evidence(id string, status verdict.Status, details map[string]any) verdict.Evidence {
	spec := c[id]
	return verdict.Evidence{
		ID: id, Tier: spec.Tier, Family: spec.Family, Status: status,
		Critical: spec.Critical && status != verdict.StatusNotEvaluated,
		Details:  details, Confidence: spec.Confidence,
		Source: verdict.Source{API: spec.API, APIVersion: spec.APIVersion},
	}
}

// Present records an observation that was made.
func (c Catalogue) Present(id string, details map[string]any) verdict.Evidence {
	return c.Evidence(id, verdict.StatusPresent, details)
}

// Absent records that the check ran and found nothing. Only a completed check
// may use it.
func (c Catalogue) Absent(id string) verdict.Evidence {
	return c.Evidence(id, verdict.StatusAbsent, nil)
}

// NotEvaluated records a check this version does not perform. It is never
// critical: an unimplemented check is a disclosed gap, not a failed reading.
func (c Catalogue) NotEvaluated(id string) verdict.Evidence {
	return c.Evidence(id, verdict.StatusNotEvaluated, nil)
}

// Unknown records why an observation is missing. The signal keeps its
// catalogue criticality, which is what stops a `yes`.
func (c Catalogue) Unknown(id string, unknown *verdict.Unknown) verdict.Evidence {
	evidence := c.Evidence(id, verdict.StatusUnknown, nil)
	evidence.Unknown = unknown
	return evidence
}

// Failed classifies a collection error and records it against the signal.
func (c Catalogue) Failed(id string, err error) verdict.Evidence {
	return c.Unknown(id, collect.Classify(err))
}

// Windowed attaches the period an observation covers, so a reader can see
// what a silence signal was silent over.
func Windowed(evidence verdict.Evidence, end time.Time, days int) verdict.Evidence {
	window := verdict.Window{Start: end.AddDate(0, 0, -days), End: end, Days: days, Grain: "P1D"}
	evidence.Window = &window
	return evidence
}

// Timestamp renders an observation time the way the output boundary's typed
// timestamp detail expects it.
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Graph issues Resource Graph queries inside the shared call budget, over one
// explicit subscription scope. A truncated answer is an error, never a page
// that quietly stands in for the whole result.
type Graph struct {
	Client       collect.GraphClient
	Limiter      *collect.Limiter
	Subscription string
	Clock        collect.Clock
}

// Query runs one query. The format takes the query's placeholders; callers
// pass already-escaped values.
func (g Graph) Query(ctx context.Context, format string, args ...any) (collect.Rows, error) {
	if g.Client == nil {
		return collect.Rows{}, &collect.Failure{ErrorCode: "NotSupported", Message: "no Resource Graph client"}
	}
	if g.Limiter != nil {
		if err := g.Limiter.Wait(ctx); err != nil {
			return collect.Rows{}, err
		}
	}
	clock := g.Clock
	if clock.Sleep == nil {
		clock = collect.SystemClock()
	}
	var rows collect.Rows
	err := collect.Retry(ctx, clock, func(ctx context.Context) error {
		var queryErr error
		rows, queryErr = g.Client.Query(ctx, collect.Query{
			Text:          fmt.Sprintf(format, args...),
			Subscriptions: []string{g.Subscription},
			Top:           collect.MaxGraphPage,
		})
		return queryErr
	})
	if err == nil && (rows.Truncated || rows.SkipToken != "") {
		return rows, collect.ErrTruncated
	}
	return rows, err
}

// QuoteIDs renders an ARM id list for a KQL `in~ (...)` clause.
func QuoteIDs(ids []string) string {
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, "'"+strings.ReplaceAll(id, "'", "''")+"'")
	}
	return strings.Join(quoted, ",")
}

// Lower is the lowercase spelling KQL comparisons against tolower() need.
func Lower(value string) string { return strings.ToLower(value) }
