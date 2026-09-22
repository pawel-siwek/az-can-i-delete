package generic

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The tag classifiers of SPEC section 5.0. They match keys and values, never
// resource names, and a match is heuristic: it is reported at its catalogue
// tier and never promoted by this layer.
var (
	protectKeys = regexp.MustCompile(`(?i)(do-?not-?delete|protected|retain|keep)`)
	expiryKeys  = regexp.MustCompile(`(?i)(expires?|ttl|delete-?after)`)
	intentTerms = regexp.MustCompile(`(?i)(^|[^a-z])(dr|bcdr|standby|failover|golden|template|image|iac|terraform|tf_|azd-env-name)([^a-z]|$)`)
	ownerKeys   = regexp.MustCompile(`(?i)^(owner|contact|team|created-?by)$`)
	falsy       = []string{"", "false", "no", "0", "off"}
)

// tagFinding is one matched tag. Key and Target are Azure free-form text and
// stay out of summaries; the report publishes Key only under untrusted.
type tagFinding struct {
	Key    string
	Target string
	Date   time.Time
}

// tagFindings is the complete classification of one resource's tags.
type tagFindings struct {
	Protect     []tagFinding
	Expired     []tagFinding
	Intent      []tagFinding
	Owner       []tagFinding
	HiddenLinks []tagFinding
}

// classifyTags applies the section 5.0 tag rules against an explicit cutoff.
// An expiry tag protects while it is in the future and only becomes an expiry
// observation once it is in the past; an unparseable date is neither.
func classifyTags(tags map[string]string, cutoff time.Time) tagFindings {
	var found tagFindings
	for key, value := range tags {
		switch {
		case protectKeys.MatchString(key) && truthy(value):
			found.Protect = append(found.Protect, tagFinding{Key: key})
		case expiryKeys.MatchString(key):
			date, ok := tagDate(value)
			switch {
			case !ok:
			case date.After(cutoff):
				found.Protect = append(found.Protect, tagFinding{Key: key, Date: date})
			default:
				found.Expired = append(found.Expired, tagFinding{Key: key, Date: date})
			}
		}
		if target, ok := hiddenLink(key, value); ok {
			found.HiddenLinks = append(found.HiddenLinks, tagFinding{Key: key, Target: target})
		}
		if intentTerms.MatchString(key) || intentTerms.MatchString(value) {
			found.Intent = append(found.Intent, tagFinding{Key: key})
		}
		if ownerKeys.MatchString(key) {
			found.Owner = append(found.Owner, tagFinding{Key: key})
		}
	}
	sortFindings(&found)
	return found
}

func truthy(value string) bool {
	return !slices.Contains(falsy, strings.ToLower(strings.TrimSpace(value)))
}

// tagDate accepts the two spellings Azure users write expiry tags in. Anything
// else is left unclassified rather than guessed into a protection decision.
func tagDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if date, err := time.Parse(layout, value); err == nil {
			return date.UTC(), true
		}
	}
	return time.Time{}, false
}

// hiddenLink reports the ARM id a hidden-link tag points at. The portal writes
// the id into the key; some producers write it into the value instead.
func hiddenLink(key, value string) (string, bool) {
	if target, ok := strings.CutPrefix(strings.ToLower(key), "hidden-link:"); ok && strings.HasPrefix(target, "/subscriptions/") {
		return target, true
	}
	if target := strings.ToLower(strings.TrimSpace(value)); strings.HasPrefix(target, "/subscriptions/") {
		return target, true
	}
	return "", false
}

// lockEvidence reports the strongest lock covering the target. Both levels
// block: a ReadOnly lock refuses the delete exactly like CanNotDelete.
func lockEvidence(locks []collect.Lock) verdict.Evidence {
	strongest := collect.Lock{}
	for _, lock := range locks {
		if !blockingLevel(lock.Level) {
			continue
		}
		if strongest.Level == "" || rank(lock) < rank(strongest) {
			strongest = lock
		}
	}
	if strongest.Level == "" {
		return absent(SignalLock)
	}
	return present(SignalLock, map[string]any{
		"level": canonicalLevel(strongest.Level), "scope": string(strongest.Scope), "lockCount": len(locks),
	})
}

func blockingLevel(level string) bool {
	return strings.EqualFold(level, "CanNotDelete") || strings.EqualFold(level, "ReadOnly")
}

func canonicalLevel(level string) string {
	if strings.EqualFold(level, "ReadOnly") {
		return "ReadOnly"
	}
	return "CanNotDelete"
}

// rank prefers CanNotDelete over ReadOnly and the closest scope, so the
// reported lock is the one a caller would have to remove first.
func rank(lock collect.Lock) int {
	scopes := map[collect.LockScope]int{collect.LockScopeResource: 0, collect.LockScopeResourceGroup: 1, collect.LockScopeSubscription: 2}
	level := 1
	if strings.EqualFold(lock.Level, "CanNotDelete") {
		level = 0
	}
	return level*3 + scopes[lock.Scope]
}

// denyEvidence reports a deny assignment covering delete. It is a BLOCKER but
// deliberately non-critical: failing to read deny assignments must not by
// itself make every verdict inconclusive.
func denyEvidence(assignments []collect.DenyAssignment) verdict.Evidence {
	blocking := 0
	for _, assignment := range assignments {
		if assignment.BlocksDelete {
			blocking++
		}
	}
	if blocking == 0 {
		return absent(SignalDenyAssignment)
	}
	return present(SignalDenyAssignment, map[string]any{"denyAssignmentCount": blocking})
}

// managedByEvidence reports resource-group ownership. Ownership only counts
// when the owning resource exists; an unresolvable owner stays unknown, because
// a dangling managedBy is not proof that nothing manages the group.
func managedByEvidence(managedBy string, ownerExists *bool) verdict.Evidence {
	switch {
	case managedBy == "":
		return absent(SignalRGManagedBy)
	case ownerExists == nil:
		return unknownAs(SignalRGManagedBy, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the owning resource could not be resolved"})
	case *ownerExists:
		return present(SignalRGManagedBy, map[string]any{"managedBy": managedBy})
	default:
		return absent(SignalRGManagedBy)
	}
}

// deploymentEvidence reports the deployment that created this resource. Only a
// successful deployment listing its id counts as provenance.
func deploymentEvidence(deployments []collect.Deployment, resourceID string, capped bool) verdict.Evidence {
	for _, deployment := range deployments {
		if !strings.EqualFold(deployment.Status, "Succeeded") {
			continue
		}
		for _, output := range deployment.OutputResources {
			if strings.EqualFold(output, resourceID) {
				return present(SignalDeployment, map[string]any{"deployedAt": timestamp(deployment.Timestamp)})
			}
		}
	}
	if capped {
		return unknownAs(SignalDeployment, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the deployment history was longer than the page budget"})
	}
	return absent(SignalDeployment)
}

// activityEvidence reports the recent-write design intent signal and the
// 90-day write count. A truncated or short log cannot establish silence, so it
// becomes unknown(partial) rather than an absence of writes.
func activityEvidence(log collect.ActivityLog, cutoff time.Time) (recent, writes verdict.Evidence) {
	recentCutoff := cutoff.AddDate(0, 0, -RecentWriteDays)
	newest := time.Time{}
	count := 0
	var callerType string
	for _, event := range log.Events {
		if !strings.EqualFold(event.Status, "Succeeded") || !isWrite(event.Operation) || cordonCaller(event) {
			continue
		}
		count++
		if event.Timestamp.After(newest) {
			newest, callerType = event.Timestamp, callerClass(event.CallerType)
		}
	}
	incomplete := log.Truncated || log.Days < RecentWriteDays
	switch {
	case newest.After(recentCutoff):
		recent = present(SignalRecentWrite, map[string]any{
			"daysAgo": int(cutoff.Sub(newest) / (24 * time.Hour)), "callerClass": callerType})
	case incomplete:
		recent = unknownAs(SignalRecentWrite, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the fixed 30-day period"})
	default:
		recent = absent(SignalRecentWrite)
	}
	switch {
	case count > 0:
		writes = present(SignalWrites, map[string]any{
			"writeCount": count, "lastWriteDaysAgo": int(cutoff.Sub(newest) / (24 * time.Hour))})
	case incomplete:
		writes = unknownAs(SignalWrites, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the fixed 90-day period"})
	default:
		writes = absent(SignalWrites)
	}
	return windowed(recent, cutoff, RecentWriteDays), windowed(writes, cutoff, WritesDays)
}

func isWrite(operation string) bool {
	operation = strings.ToLower(operation)
	return strings.HasSuffix(operation, "/write") || strings.HasSuffix(operation, "/action")
}

// cordonCaller excludes this tool's own cordon writes, so a scream test does
// not later read as somebody using the resource.
func cordonCaller(event collect.ActivityEvent) bool {
	return strings.Contains(strings.ToLower(event.Caller), "azcid")
}

func callerClass(callerType string) string {
	switch strings.ToLower(callerType) {
	case "serviceprincipal", "application":
		return "servicePrincipal"
	case "managedidentity", "msi":
		return "managedIdentity"
	case "user":
		return "user"
	default:
		return "unknown"
	}
}

// peEvidence reports approved private endpoint connections from the GET body.
// A type whose body does not carry the collection is not evaluated here rather
// than reported as having none.
func peEvidence(properties map[string]any) verdict.Evidence {
	raw, ok := properties["privateEndpointConnections"]
	if !ok {
		return notEvaluated(SignalPEConnections)
	}
	connections, ok := raw.([]any)
	if !ok {
		return unknownAs(SignalPEConnections, &verdict.Unknown{
			Code: verdict.UnkUnsupported, Message: "the private endpoint collection had an unexpected shape"})
	}
	approved := 0
	for _, connection := range connections {
		if approvedConnection(connection) {
			approved++
		}
	}
	if approved == 0 {
		return absent(SignalPEConnections)
	}
	return present(SignalPEConnections, map[string]any{"privateEndpointCount": approved})
}

func approvedConnection(connection any) bool {
	body, ok := connection.(map[string]any)
	if !ok {
		return false
	}
	properties, ok := body["properties"].(map[string]any)
	if !ok {
		return false
	}
	state, ok := properties["privateLinkServiceConnectionState"].(map[string]any)
	if !ok {
		return false
	}
	status, _ := state["status"].(string)
	return strings.EqualFold(status, "Approved")
}

// advisorEvidence reports an Advisor cost recommendation. It corroborates
// idleness and never establishes it on its own.
func advisorEvidence(rows collect.Rows) verdict.Evidence {
	for _, row := range rows.Rows {
		if category, _ := row["category"].(string); strings.EqualFold(category, "Cost") {
			return present(SignalAdvisor, map[string]any{"recommendationCount": len(rows.Rows)})
		}
	}
	return absent(SignalAdvisor)
}

// sortFindings keeps every report deterministic whatever order the tag map
// iterated in.
func sortFindings(found *tagFindings) {
	for _, group := range [][]tagFinding{found.Protect, found.Expired, found.Intent, found.Owner, found.HiddenLinks} {
		slices.SortFunc(group, func(a, b tagFinding) int { return strings.Compare(a.Key+a.Target, b.Key+b.Target) })
	}
}
