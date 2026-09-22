// Package assess runs one resource through the whole pipeline: the pinned ARM
// GET that establishes existence, the generic signal layer, the type's Required
// catalogue, the pure verdict rules and the output boundary. It owns no rules
// of its own — every decision belongs to internal/verdict, and every string a
// person reads belongs to the output policy.
package assess

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/disk"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/network"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/site"
	"github.com/pawel-siwek/az-can-i-delete/internal/storage"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
	"github.com/pawel-siwek/az-can-i-delete/internal/vm"
)

// Window bounds. The default is 30 days; below 30 a `yes` is unreachable by
// construction, and above 93 there is no metric retention to observe.
const (
	MinWindowDays     = 7
	MaxWindowDays     = 93
	DefaultWindowDays = verdict.DefaultRequestedDays
	// ResourceChangesDays is the Resource Graph change retention the report
	// discloses; it is a coverage statement, not a verdict input.
	ResourceChangesDays = 14
)

// ErrUnsupportedType is returned for a resource type with no analyzer. It is a
// refusal, not a verdict: the tool says nothing about a type it cannot assess.
var ErrUnsupportedType = errors.New("unsupported resource type")

// Options are the per-run choices a caller makes. Cutoff is the explicit
// observation time; nothing below this package reads a clock.
type Options struct {
	Requested  verdict.Window
	Cutoff     time.Time
	RedactTags bool
	DataPlane  bool
}

// Runner holds the collection clients and the policy catalogue for a process.
type Runner struct {
	Clients     collect.Clients
	Graph       *collect.Limiter
	Policies    map[string]output.SignalPolicy
	ToolVersion string
}

// New builds a runner over ready clients. The Resource Graph limiter is shared
// across every target so one run cannot exceed the call budget by fanning out.
func New(clients collect.Clients, toolVersion string) *Runner {
	policies := generic.Policies()
	for _, analyzer := range []map[string]output.SignalPolicy{disk.Policies(), network.Policies(), storage.Policies(), vm.Policies(), site.Policies()} {
		for id, policy := range analyzer {
			policies[id] = policy
		}
	}
	return &Runner{
		Clients:     clients,
		Graph:       collect.NewGraphLimiter(collect.SystemClock()),
		Policies:    policies,
		ToolVersion: toolVersion,
	}
}

// analyze runs the type's analyzer, if it has one. A type without an analyzer
// is still assessed: its generic evidence is collected and its Required signals
// are reported missing, which is why it cannot come out as `yes`. The analyzers
// reuse the generic layer's observations rather than collecting the Activity
// Log or the graph probe again, so one assessment stays inside one call budget.
func (r *Runner) analyze(ctx context.Context, target armid.Target, resource collect.Resource, opts Options, collected generic.Result) []verdict.Evidence {
	switch {
	case strings.EqualFold(target.ResourceType, disk.ResourceType):
		return disk.Collect(ctx, disk.Input{
			Target: target, Resource: resource, Requested: opts.Requested,
			Cutoff: opts.Cutoff.UTC(), Clients: r.Clients, Graph: r.Graph, Generic: collected,
		})
	case network.Supports(target.ResourceType):
		return network.Collect(ctx, network.Input{
			Target: target, Resource: resource, Requested: opts.Requested,
			Cutoff: opts.Cutoff.UTC(), Clients: r.Clients, Graph: r.Graph, Generic: collected,
		})
	case strings.EqualFold(target.ResourceType, storage.ResourceType):
		return storage.Collect(ctx, storage.Input{
			Target: target, Resource: resource, Requested: opts.Requested,
			Cutoff: opts.Cutoff.UTC(), Clients: r.Clients, Graph: r.Graph, Generic: collected,
		})
	case site.Supports(target.ResourceType):
		return site.Collect(ctx, site.Input{
			Target: target, Resource: resource, Requested: opts.Requested,
			Cutoff: opts.Cutoff.UTC(), Clients: r.Clients, Graph: r.Graph, Generic: collected,
		})
	case strings.EqualFold(target.ResourceType, vm.ResourceType):
		return vm.Collect(ctx, vm.Input{
			Target: target, Resource: resource, Requested: opts.Requested,
			Cutoff: opts.Cutoff.UTC(), Clients: r.Clients, Graph: r.Graph, Generic: collected,
		})
	default:
		return nil
	}
}

// ParseWindow turns the --window flag into an explicit observation window.
// A window shorter than 30 days is accepted and can only yield `no` or
// `tentative`; the rules, not this parser, enforce that.
func ParseWindow(flag string, cutoff time.Time) (verdict.Window, error) {
	days := DefaultWindowDays
	if trimmed := strings.TrimSpace(flag); trimmed != "" {
		parsed, err := strconv.Atoi(strings.TrimSuffix(strings.ToLower(trimmed), "d"))
		if err != nil {
			return verdict.Window{}, fmt.Errorf("window must be a number of days, such as 30d")
		}
		days = parsed
	}
	if days < MinWindowDays || days > MaxWindowDays {
		return verdict.Window{}, fmt.Errorf("window must be between %dd and %dd", MinWindowDays, MaxWindowDays)
	}
	end := cutoff.UTC()
	return verdict.Window{Start: end.AddDate(0, 0, -days), End: end, Days: days, Grain: "P1D"}, nil
}

// Check assesses one target. A missing resource is a not-found outcome, an
// unsupported type is a refusal, and anything that prevented a complete
// assessment is an error — none of the three is ever a verdict.
func (r *Runner) Check(ctx context.Context, target armid.Target, opts Options) (output.Outcome, error) {
	apiVersion, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return output.Failed(output.Runtime), fmt.Errorf("%w: %s", ErrUnsupportedType, target.ResourceType)
	}
	resource, err := r.Clients.ARM.Get(ctx, target.ID, apiVersion)
	if err != nil {
		if collect.NotFound(err) {
			return output.Failed(output.NotFound), nil
		}
		return output.Failed(output.Runtime), fmt.Errorf("reading %s: %w", target.ResourceType, err)
	}

	collected := generic.Collect(ctx, generic.Input{
		Target:    target,
		Resource:  resource,
		Requested: opts.Requested,
		Cutoff:    opts.Cutoff.UTC(),
		Clients:   r.Clients,
		Graph:     r.Graph,
	})

	evidence := append(collected.Evidence, r.analyze(ctx, target, resource, opts, collected)...)
	report, err := output.Build(r.reportInput(target, resource, opts, collected, evidence), output.Config{
		ToolVersion: r.ToolVersion,
		RulesDate:   rules.Date(),
		RedactTags:  opts.RedactTags,
		Policies:    r.Policies,
	})
	if err != nil {
		return output.Failed(output.Runtime), fmt.Errorf("building the report for %s: %w", target.ResourceType, err)
	}
	return output.Completed(report), nil
}

// reportInput assembles the report's observed context. Azure free-form text
// travels only here, under the metadata the output boundary sanitizes.
func (r *Runner) reportInput(target armid.Target, resource collect.Resource, opts Options, collected generic.Result, evidence []verdict.Evidence) output.Input {
	tags := make([]output.Tag, 0, len(resource.Tags))
	for _, key := range collected.Metadata.TagKeys {
		tags = append(tags, output.Tag{Key: key, Value: resource.Tags[key]})
	}
	changesDays := 0
	if collected.ARGVisible {
		changesDays = ResourceChangesDays
	}
	return output.Input{
		ResourceID:   target.ID,
		GeneratedAt:  opts.Cutoff.UTC(),
		HostingClass: hostingClass(target.ResourceType),
		Assessment: verdict.Input{
			Type:      target.ResourceType,
			Evidence:  evidence,
			Age:       collected.Age,
			Requested: opts.Requested,
			Required:  verdict.RequiredForType(target.ResourceType),
		},
		Metadata: output.Metadata{
			Name:          target.Name,
			ResourceGroup: target.ResourceGroup,
			Callers:       collected.Metadata.Callers,
			Tags:          tags,
		},
		Scope: output.Scope{
			ARGSubscriptionsQueried: []string{target.SubscriptionID},
			ARGVisible:              collected.ARGVisible,
			ActivityLogDays:         collected.ActivityLogDays,
			ResourceChangesDays:     changesDays,
		},
	}
}

// hostingClass is the App Service hosting class. Every other type is explicitly
// not applicable rather than silently blank.
func hostingClass(resourceType string) string {
	switch strings.ToLower(resourceType) {
	case "microsoft.web/sites", "microsoft.web/sites/slots":
		// The site analyzer reports the real class as a signal of its own; the
		// report header states it as unknown rather than duplicating the rule.
		return "unknown"
	default:
		return "not-applicable"
	}
}
