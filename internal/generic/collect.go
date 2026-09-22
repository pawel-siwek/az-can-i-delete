package generic

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Input is everything the generic layer needs. The target GET has already
// succeeded (a 404 ends the run before this layer), Cutoff is the explicit
// observation time and Graph is the shared Resource Graph limiter.
type Input struct {
	Target    armid.Target
	Resource  collect.Resource
	Requested verdict.Window
	Cutoff    time.Time
	Clients   collect.Clients
	Graph     *collect.Limiter
}

// Result is the generic evidence in catalogue order, the resolved age, and the
// observations an analyzer reuses rather than collecting a second time. An
// analyzer that needs the Activity Log or the graph's visibility takes them
// from here, so one run stays inside one call budget.
type Result struct {
	Evidence        []verdict.Evidence
	Age             verdict.Age
	ARGVisible      bool
	ARGUnknown      *verdict.Unknown
	ActivityLog     collect.ActivityLog
	ActivityLogRead bool
	ActivityLogDays int
	Changes         []age.ResourceChange
	ChangesRead     bool
	ManagedBy       string
	Metadata        Metadata
}

// Metadata is the Azure free-form text the report may publish under untrusted.
// It never reaches a summary and is kept separate from typed evidence details.
type Metadata struct {
	TagKeys []string
	Callers []string
}

// Collect runs the generic layer: the Resource Graph visibility probe first,
// then every other signal inside the shared budgets. A signal that cannot be
// read is reported as unknown with its catalogue criticality, so an unreadable
// blocker keeps `yes` out of reach instead of disappearing.
func Collect(ctx context.Context, in Input) Result {
	probe := probeGraph(ctx, in)
	tags := classifyTags(in.Resource.Tags, in.Cutoff)

	var history historyGroup
	var deployments deploymentGroup
	var managed managedGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalLock, Run: lockSignal(in)},
		{ID: SignalDenyAssignment, Run: denySignal(in)},
		{ID: SignalRGManagedBy, Run: managed.run(in, probe)},
		{ID: SignalHiddenLink, Run: hiddenLinkSignal(in, probe, tags)},
		{ID: SignalAdvisor, Run: advisorSignal(in, probe)},
		{ID: SignalDeployment, Run: deployments.run(in)},
		{ID: SignalRecentWrite, Run: history.run(in, probe)},
	})

	collected := map[string]verdict.Evidence{}
	for _, outcome := range outcomes {
		for _, e := range outcome.Evidence {
			collected[e.ID] = e
		}
		if outcome.Unknown != nil {
			for _, id := range groupIDs(outcome.ID) {
				collected[id] = unknownAs(id, outcome.Unknown)
			}
		}
	}
	collected[SignalARMGet] = armGetEvidence(in.Resource)
	collected[SignalARGVisible] = probe.evidence
	collected[SignalPEConnections] = peEvidence(in.Resource.Properties)
	collected[SignalDNSRecords] = notEvaluated(SignalDNSRecords)
	collected[SignalRoleAssignments] = notEvaluated(SignalRoleAssignments)
	collected[SignalPolicyState] = notEvaluated(SignalPolicyState)
	for id, e := range tagEvidence(tags, collected) {
		collected[id] = e
	}

	result := Result{
		Age:             resolveAge(in, history, deployments.deployments),
		ARGVisible:      probe.visible,
		ARGUnknown:      probe.unknown,
		ActivityLog:     history.log,
		ActivityLogRead: history.read,
		ActivityLogDays: history.log.Days,
		Changes:         history.changes,
		ChangesRead:     history.changesRead,
		ManagedBy:       managed.managedBy,
		Metadata:        Metadata{TagKeys: tagKeys(tags), Callers: history.callers},
	}
	for _, id := range Signals {
		e, ok := collected[id]
		if !ok {
			e = unknownAs(id, &verdict.Unknown{Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		result.Evidence = append(result.Evidence, e)
	}
	return result
}

// groupIDs maps a failed collection group onto every signal it would have
// produced, so one failed call cannot silence a second signal.
func groupIDs(groupID string) []string {
	switch groupID {
	case SignalHiddenLink:
		return []string{SignalHiddenLink, SignalHiddenLinkDead}
	case SignalRecentWrite:
		return []string{SignalRecentWrite, SignalWrites}
	default:
		return []string{groupID}
	}
}

func armGetEvidence(resource collect.Resource) verdict.Evidence {
	details := map[string]any{}
	if state := provisioningState(resource); state != "" {
		details["provisioningState"] = state
	}
	return present(SignalARMGet, details)
}

// provisioningState is reported only when it is one of the documented terminal
// or transient states; anything else is left out rather than echoed.
func provisioningState(resource collect.Resource) string {
	state := resource.ProvisioningState
	if state == "" {
		state, _ = resource.Properties["provisioningState"].(string)
	}
	for _, known := range []string{"Succeeded", "Failed", "Canceled", "Creating", "Updating", "Deleting"} {
		if strings.EqualFold(state, known) {
			return known
		}
	}
	return ""
}

// tagEvidence turns the tag classification into the five tag signals. The
// hidden-link pair is decided by the Resource Graph existence check and is only
// filled in here when that check did not run.
func tagEvidence(tags tagFindings, collected map[string]verdict.Evidence) map[string]verdict.Evidence {
	out := map[string]verdict.Evidence{
		SignalTagProtect: absent(SignalTagProtect),
		SignalTagExpired: absent(SignalTagExpired),
		SignalTagIntent:  absent(SignalTagIntent),
		SignalTagOwner:   absent(SignalTagOwner),
	}
	if len(tags.Protect) > 0 {
		out[SignalTagProtect] = present(SignalTagProtect, map[string]any{"matchCount": len(tags.Protect)})
	}
	if len(tags.Expired) > 0 {
		out[SignalTagExpired] = present(SignalTagExpired, map[string]any{
			"matchCount": len(tags.Expired), "expiredAt": signal.Timestamp(tags.Expired[0].Date)})
	}
	if len(tags.Intent) > 0 {
		out[SignalTagIntent] = present(SignalTagIntent, map[string]any{"matchCount": len(tags.Intent)})
	}
	if len(tags.Owner) > 0 {
		out[SignalTagOwner] = present(SignalTagOwner, map[string]any{"matchCount": len(tags.Owner)})
	}
	for _, id := range []string{SignalHiddenLink, SignalHiddenLinkDead} {
		if _, ok := collected[id]; !ok {
			out[id] = absent(id)
		}
	}
	return out
}

func tagKeys(tags tagFindings) []string {
	var keys []string
	for _, group := range [][]tagFinding{tags.Protect, tags.Expired, tags.Intent, tags.Owner, tags.HiddenLinks} {
		for _, finding := range group {
			if !slices.Contains(keys, finding.Key) {
				keys = append(keys, finding.Key)
			}
		}
	}
	return keys
}

// errNoGraphVisibility marks a graph-backed source that could not be read
// because the visibility probe did not find the target.
var errNoGraphVisibility = errors.New("no Resource Graph visibility")

// graphProbe is the K0 result. Visible is true only when the target's own row
// came back: SPEC section 3.1 turns a successful GET with zero rows into
// unknown(permission) for every Resource Graph signal.
type graphProbe struct {
	visible  bool
	evidence verdict.Evidence
	unknown  *verdict.Unknown
}

func probeGraph(ctx context.Context, in Input) graphProbe {
	rows, err := query(ctx, in, "resources | where id =~ '%s' | project id, type, tags, systemData", in.Target.ID)
	switch {
	case err != nil:
		unknown := collect.Classify(err)
		return graphProbe{evidence: unknownAs(SignalARGVisible, unknown), unknown: unknown}
	case len(rows.Rows) == 0:
		// The caller read the resource through ARM, so it exists. No Resource
		// Graph row means the caller lacks subscription-scope Reader or the
		// resource is younger than the graph's ingestion delay.
		unknown := &verdict.Unknown{Code: verdict.UnkPermission,
			Message: "the target is not visible in Resource Graph, so no graph-backed signal could be collected"}
		return graphProbe{evidence: absent(SignalARGVisible), unknown: unknown}
	default:
		return graphProbe{visible: true, evidence: present(SignalARGVisible, map[string]any{"rowCount": len(rows.Rows)})}
	}
}

// graph is the shared bounded Resource Graph runner for this target.
func graph(in Input) signal.Graph {
	return signal.Graph{Client: in.Clients.Graph, Limiter: in.Graph, Subscription: in.Target.SubscriptionID}
}

func query(ctx context.Context, in Input, format string, args ...any) (collect.Rows, error) {
	return graph(in).Query(ctx, format, args...)
}

// argUnavailable reports the unknown every graph-backed signal must carry when
// the probe did not establish visibility.
func (p graphProbe) argUnavailable() *verdict.Unknown { return p.unknown }

// lockSignal collects management locks at all three scopes. A failure at any
// scope is the signal's unknown: a lock that could not be read must not read
// as absent.
func lockSignal(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		var all []collect.Lock
		for _, scope := range lockScopes(in.Target) {
			locks, err := in.Clients.ARM.Locks(ctx, scope.id)
			if err != nil {
				return nil, err
			}
			for _, lock := range locks {
				lock.Scope = scope.scope
				all = append(all, lock)
			}
		}
		return []verdict.Evidence{lockEvidence(all)}, nil
	}
}

type scopedID struct {
	id    string
	scope collect.LockScope
}

func lockScopes(target armid.Target) []scopedID {
	scopes := []scopedID{{target.ID, collect.LockScopeResource}}
	if target.ResourceGroup != "" {
		scopes = append(scopes, scopedID{resourceGroupID(target), collect.LockScopeResourceGroup})
	}
	return append(scopes, scopedID{"/subscriptions/" + target.SubscriptionID, collect.LockScopeSubscription})
}

func resourceGroupID(target armid.Target) string {
	return "/subscriptions/" + target.SubscriptionID + "/resourceGroups/" + target.ResourceGroup
}

// denySignal reads the deny assignments covering the target.
func denySignal(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		assignments, err := in.Clients.ARM.DenyAssignments(ctx, in.Target.ID)
		if err != nil {
			return nil, err
		}
		return []verdict.Evidence{denyEvidence(assignments)}, nil
	}
}

// managedGroup reads the resource group's managedBy and confirms the owner
// exists. The owner is kept because an analyzer may need to know what manages
// the group, for example an AKS cluster that owns a persistent volume.
type managedGroup struct {
	managedBy string
}

func (g *managedGroup) run(in Input, probe graphProbe) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if !probe.visible {
			return []verdict.Evidence{unknownAs(SignalRGManagedBy, probe.argUnavailable())}, nil
		}
		if in.Target.ResourceGroup == "" {
			return []verdict.Evidence{absent(SignalRGManagedBy)}, nil
		}
		rows, err := query(ctx, in,
			"resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' and subscriptionId == '%s' and name =~ '%s' | project id, managedBy, tags",
			in.Target.SubscriptionID, in.Target.ResourceGroup)
		if err != nil {
			return nil, err
		}
		managedBy := ""
		for _, row := range rows.Rows {
			if value, _ := row["managedBy"].(string); value != "" {
				managedBy = value
			}
		}
		if managedBy == "" {
			return []verdict.Evidence{absent(SignalRGManagedBy)}, nil
		}
		g.managedBy = managedBy
		exists, err := idsExist(ctx, in, []string{managedBy})
		if err != nil {
			return nil, err
		}
		owner := exists[strings.ToLower(managedBy)]
		return []verdict.Evidence{managedByEvidence(managedBy, &owner)}, nil
	}
}

// hiddenLinkSignal resolves hidden-link tags. A link whose target exists is a
// dependency; a link whose target is gone is information, never a dependency.
func hiddenLinkSignal(in Input, probe graphProbe, tags tagFindings) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if len(tags.HiddenLinks) == 0 {
			return []verdict.Evidence{absent(SignalHiddenLink), absent(SignalHiddenLinkDead)}, nil
		}
		if !probe.visible {
			return []verdict.Evidence{
				unknownAs(SignalHiddenLink, probe.argUnavailable()),
				unknownAs(SignalHiddenLinkDead, probe.argUnavailable()),
			}, nil
		}
		var targets []string
		for _, link := range tags.HiddenLinks {
			targets = append(targets, link.Target)
		}
		exists, err := idsExist(ctx, in, targets)
		if err != nil {
			return nil, err
		}
		live, dangling := 0, 0
		for _, target := range targets {
			if exists[strings.ToLower(target)] {
				live++
				continue
			}
			dangling++
		}
		evidence := []verdict.Evidence{absent(SignalHiddenLink), absent(SignalHiddenLinkDead)}
		if live > 0 {
			evidence[0] = present(SignalHiddenLink, map[string]any{"linkCount": live})
		}
		if dangling > 0 {
			evidence[1] = present(SignalHiddenLinkDead, map[string]any{"linkCount": dangling})
		}
		return evidence, nil
	}
}

// idsExist answers the K3 existence question for a set of ARM ids.
func idsExist(ctx context.Context, in Input, ids []string) (map[string]bool, error) {
	rows, err := query(ctx, in, "resources | where id in~ (%s) | project id", signal.QuoteIDs(ids))
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, row := range rows.Rows {
		if id, _ := row["id"].(string); id != "" {
			found[strings.ToLower(id)] = true
		}
	}
	return found, nil
}

// advisorSignal reads the Advisor recommendations that corroborate idleness.
func advisorSignal(in Input, probe graphProbe) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if !probe.visible {
			return []verdict.Evidence{unknownAs(SignalAdvisor, probe.argUnavailable())}, nil
		}
		rows, err := query(ctx, in,
			"advisorresources | where type =~ 'microsoft.advisor/recommendations' | where tolower(tostring(properties.resourceMetadata.resourceId)) == '%s' | project recType = tostring(properties.recommendationTypeId), category = tostring(properties.category), impact = tostring(properties.impact)",
			strings.ToLower(in.Target.ID))
		if err != nil {
			return nil, err
		}
		return []verdict.Evidence{advisorEvidence(rows)}, nil
	}
}

// deploymentGroup looks for the deployment that created the target and keeps
// the history, which is also one of the age chain's seven sources.
type deploymentGroup struct {
	deployments []collect.Deployment
}

func (g *deploymentGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if in.Target.ResourceGroup == "" {
			return []verdict.Evidence{absent(SignalDeployment)}, nil
		}
		deployments, err := in.Clients.ARM.Deployments(ctx, resourceGroupID(in.Target), collect.MaxDeployments)
		if err != nil {
			return nil, err
		}
		g.deployments = deployments
		return []verdict.Evidence{deploymentEvidence(deployments, in.Target.ID, len(deployments) >= collect.MaxDeployments)}, nil
	}
}

// historyGroup collects the Activity Log and the Resource Changes history. It
// produces both Activity Log signals and three of the age chain's sources, so a
// failure here leaves the age unknown rather than inventing a young or old
// resource.
type historyGroup struct {
	log         collect.ActivityLog
	read        bool
	changes     []age.ResourceChange
	changesRead bool
	truncated   bool
	callers     []string
}

func (g *historyGroup) run(in Input, probe graphProbe) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		window := verdict.Window{Start: in.Cutoff.AddDate(0, 0, -WritesDays), End: in.Cutoff, Days: WritesDays, Grain: "P1D"}
		log, err := in.Clients.ActivityLog.Events(ctx, in.Target.ID, window)
		if err != nil {
			return nil, err
		}
		g.log, g.read = log, true
		for _, event := range log.Events {
			if event.Caller != "" && !slices.Contains(g.callers, event.Caller) {
				g.callers = append(g.callers, event.Caller)
			}
		}
		changes, changesErr := resourceChanges(ctx, in, probe)
		g.changes, g.changesRead = changes, changesErr == nil
		g.truncated = log.Truncated || changesErr != nil
		recent, writes := activityEvidence(log, in.Cutoff)
		return []verdict.Evidence{recent, writes}, nil
	}
}

// resolveAge runs the age chain over everything the run actually read. An
// unread Activity Log cannot infer an absence of events, so the chain is told
// the log did not succeed and the age stays unknown.
func resolveAge(in Input, history historyGroup, deployments []collect.Deployment) verdict.Age {
	normalized := make([]age.Deployment, 0, len(deployments))
	for _, deployment := range deployments {
		normalized = append(normalized, deployment.Deployment)
	}
	return age.ResolveAge(age.Input{
		ResourceID:           in.Target.ID,
		Cutoff:               in.Cutoff,
		RPTimestamp:          rpTimestamp(in.Resource),
		ActivityLog:          history.log.AgeEvents(),
		ResourceChanges:      history.changes,
		Deployments:          normalized,
		ActivityLogSucceeded: history.read,
		ActivityLogTruncated: history.truncated,
		ActivityLogDays:      history.log.Days,
	})
}

// resourceChanges reads the 14-day change history. It is best effort: without
// it the age chain simply has one source fewer and stays honest about it.
func resourceChanges(ctx context.Context, in Input, probe graphProbe) ([]age.ResourceChange, error) {
	if !probe.visible {
		return nil, errNoGraphVisibility
	}
	rows, err := query(ctx, in,
		"resourcechanges | extend targetId = tolower(tostring(properties.targetResourceId)), changeType = tostring(properties.changeType), ts = todatetime(properties.changeAttributes.timestamp), op = tostring(properties.changeAttributes.operation) | where targetId == '%s' | project ts, changeType, op | order by ts asc",
		strings.ToLower(in.Target.ID))
	if err != nil {
		return nil, err
	}
	var changes []age.ResourceChange
	for _, row := range rows.Rows {
		timestamp, ok := rowTime(row["ts"])
		if !ok {
			continue
		}
		changeType, _ := row["changeType"].(string)
		operation, _ := row["op"].(string)
		changes = append(changes, age.ResourceChange{
			ResourceID: in.Target.ID, Timestamp: timestamp, ChangeType: changeType, Operation: operation,
		})
	}
	return changes, nil
}

// rpTimestamp reads the resource provider's own creation timestamp when the
// body carries one for the current object.
func rpTimestamp(resource collect.Resource) *time.Time {
	for _, key := range []string{"createdAt", "timeCreated", "creationTime"} {
		if value, ok := rowTime(resource.SystemData[key]); ok {
			return &value
		}
		if value, ok := rowTime(resource.Properties[key]); ok {
			return &value
		}
	}
	return nil
}

func rowTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), true
	case string:
		parsed, err := time.Parse(time.RFC3339, typed)
		if err != nil {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	default:
		return time.Time{}, false
	}
}
