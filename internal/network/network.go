// Package network holds the analyzers for the leftovers a deleted virtual
// machine leaves behind: network interfaces, public IP addresses and network
// security groups. All three are structural — their own body says what is
// attached to them — and all three share the same question about time: has
// anything touched this for long enough to call it abandoned?
package network

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The resource types these analyzers answer for.
const (
	NICType      = "Microsoft.Network/networkInterfaces"
	PublicIPType = "Microsoft.Network/publicIPAddresses"
	NSGType      = "Microsoft.Network/networkSecurityGroups"
)

// IdleDays is the fixed period the three detachment signals ask about, and
// ChangeRetention is how far the Resource Graph change history reaches back.
const (
	IdleDays        = 30
	ChangeRetention = 14
)

// Input is what an analyzer needs on top of the generic layer's result, whose
// Activity Log, change history and graph probe it reuses.
type Input struct {
	Target    armid.Target
	Resource  collect.Resource
	Requested verdict.Window
	Cutoff    time.Time
	Clients   collect.Clients
	Graph     *collect.Limiter
	Generic   generic.Result
}

func (in Input) graph() signal.Graph {
	return signal.Graph{Client: in.Clients.Graph, Limiter: in.Graph, Subscription: in.Target.SubscriptionID}
}

func (in Input) resourceGroupID() string {
	return "/subscriptions/" + in.Target.SubscriptionID + "/resourceGroups/" + in.Target.ResourceGroup
}

// Supports reports whether this package analyzes a type.
func Supports(resourceType string) bool {
	switch {
	case strings.EqualFold(resourceType, NICType),
		strings.EqualFold(resourceType, PublicIPType),
		strings.EqualFold(resourceType, NSGType):
		return true
	default:
		return false
	}
}

// Collect dispatches to the analyzer for the target's type.
func Collect(ctx context.Context, in Input) []verdict.Evidence {
	switch {
	case strings.EqualFold(in.Target.ResourceType, NICType):
		return collectNIC(ctx, in)
	case strings.EqualFold(in.Target.ResourceType, PublicIPType):
		return collectPublicIP(ctx, in)
	case strings.EqualFold(in.Target.ResourceType, NSGType):
		return collectNSG(ctx, in)
	default:
		return nil
	}
}

// order returns the collected evidence in catalogue order, reporting any
// signal that produced no observation rather than leaving it out.
func order(catalogue signal.Catalogue, signals []string, collected map[string]verdict.Evidence) []verdict.Evidence {
	evidence := make([]verdict.Evidence, 0, len(signals))
	for _, id := range signals {
		found, ok := collected[id]
		if !ok {
			found = catalogue.Unknown(id, &verdict.Unknown{
				Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		evidence = append(evidence, found)
	}
	return evidence
}

// structural derives the "nothing is attached" signal. It is only absence when
// every blocking source was actually read: a blocker that could not be read
// leaves the structural signal unknown, which is what keeps a `yes` away.
func structural(catalogue signal.Catalogue, id string, blockers []verdict.Evidence) verdict.Evidence {
	for _, blocker := range blockers {
		switch blocker.Status {
		case verdict.StatusPresent:
			return catalogue.Absent(id)
		case verdict.StatusUnknown:
			return catalogue.Unknown(id, blocker.Unknown)
		}
	}
	return catalogue.Present(id, map[string]any{"attachmentCount": 0})
}

// idle answers "nothing has touched this for at least 30 days" from the
// Activity Log and the change history the generic layer already read. Every
// source must have answered: an unread log or change history is unknown, never
// a quiet resource. groupOperation, when set, additionally requires that no
// such operation succeeded in the resource group, which is how a NIC detached
// by a deleted virtual machine is caught (the detach is not logged on the NIC).
func idle(ctx context.Context, in Input, catalogue signal.Catalogue, id, groupOperation string) verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		return catalogue.Unknown(id, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Activity Log could not be read"})
	}
	if in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < IdleDays {
		return catalogue.Unknown(id, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the fixed 30-day period"})
	}
	if !in.Generic.ChangesRead {
		return catalogue.Unknown(id, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Resource Graph change history could not be read"})
	}
	since := in.Cutoff.AddDate(0, 0, -IdleDays)
	for _, event := range in.Generic.ActivityLog.Events {
		if event.Timestamp.Before(since) || !strings.EqualFold(event.Status, "Succeeded") {
			continue
		}
		if changed(event.Operation) && !strings.Contains(strings.ToLower(event.Caller), "azcid") {
			return signal.Windowed(catalogue.Absent(id), in.Cutoff, IdleDays)
		}
	}
	changeSince := in.Cutoff.AddDate(0, 0, -ChangeRetention)
	for _, change := range in.Generic.Changes {
		if !change.Timestamp.Before(changeSince) {
			return signal.Windowed(catalogue.Absent(id), in.Cutoff, IdleDays)
		}
	}
	if groupOperation != "" {
		evidence, quiet := groupQuiet(ctx, in, catalogue, id, groupOperation)
		if !quiet {
			return evidence
		}
	}
	return signal.Windowed(catalogue.Present(id, map[string]any{"quietDays": IdleDays}), in.Cutoff, IdleDays)
}

// groupQuiet checks the resource group's own Activity Log for an operation
// that would have detached this resource without writing to it.
func groupQuiet(ctx context.Context, in Input, catalogue signal.Catalogue, id, operation string) (verdict.Evidence, bool) {
	if in.Clients.ActivityLog == nil || in.Target.ResourceGroup == "" {
		return catalogue.Unknown(id, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the resource group's Activity Log could not be read"}), false
	}
	window := verdict.Window{Start: in.Cutoff.AddDate(0, 0, -IdleDays), End: in.Cutoff, Days: IdleDays, Grain: "P1D"}
	log, err := in.Clients.ActivityLog.Events(ctx, in.resourceGroupID(), window)
	if err != nil {
		return catalogue.Failed(id, err), false
	}
	if log.Truncated || log.Days < IdleDays {
		return catalogue.Unknown(id, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the resource group's Activity Log did not cover the fixed 30-day period"}), false
	}
	for _, event := range log.Events {
		if strings.EqualFold(event.Status, "Succeeded") &&
			strings.Contains(strings.ToLower(event.Operation), operation) {
			return signal.Windowed(catalogue.Absent(id), in.Cutoff, IdleDays), false
		}
	}
	return verdict.Evidence{}, true
}

func changed(operation string) bool {
	operation = strings.ToLower(operation)
	return strings.HasSuffix(operation, "/write") || strings.HasSuffix(operation, "/delete")
}

// reference reads an ARM id out of a nested property, for example
// properties.virtualMachine.id.
func reference(properties map[string]any, path ...string) string {
	current := properties
	for i, key := range path {
		if i == len(path)-1 {
			value, _ := current[key].(string)
			return value
		}
		next, ok := current[key].(map[string]any)
		if !ok {
			return ""
		}
		current = next
	}
	return ""
}

// list returns a nested array, for example properties.subnets.
func list(properties map[string]any, key string) []any {
	values, _ := properties[key].([]any)
	return values
}

// blocker reports a single-owner attachment: present when the id is set.
func blocker(catalogue signal.Catalogue, id, owner string) verdict.Evidence {
	if owner == "" {
		return catalogue.Absent(id)
	}
	return catalogue.Present(id, map[string]any{"owner": owner})
}
