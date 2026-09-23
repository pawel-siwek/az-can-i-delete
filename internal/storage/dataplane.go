package storage

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The opt-in data-plane walk answers one question the control plane cannot:
// when was something last written inside this account?
//
// It is off unless the caller passed --data-plane, because it reads inside
// containers and that is a different kind of access from reading the account's
// shape. It is OAuth only: no account key is acquired, no SAS is minted, and a
// caller without data access gets unknown(permission), never an empty answer.
//
// The walk is a sample, not a survey. SPEC section 3.2 bounds it at five
// containers, and within each container twelve calls and three seconds, which
// is enough to descend the y=/m=/d=/h= partitions that logging producers write
// and nowhere near enough to prove a whole account is idle. The limitation
// printed with every `yes` says so.

// The bounds of SPEC section 3.2, which are the contract rather than a tuning
// knob: a wider walk would read more of somebody's data for a weaker claim.
const (
	maxWalkedContainers = 5
	maxCallsPerWalk     = 12
	maxTimePerWalk      = 3 * time.Second
)

// freshnessWindow is how recently something must have been written for the
// walk to count as live activity rather than as a date worth printing.
const freshnessWindow = 30 * 24 * time.Hour

// dataPlaneFreshness reports the most recent write the walk found.
//
// Present at LIVE_ACTIVITY when that write is inside the freshness window;
// present at INFO when it is older, because a stale date is a fact about the
// account rather than evidence of use. Anything the walk could not complete is
// unknown, and the walk being switched off is not_evaluated — an option nobody
// exercised is a disclosed gap, not a reading.
func dataPlaneFreshness(ctx context.Context, in Input, lists []childList) verdict.Evidence {
	if in.Clients.DataPlane == nil {
		return Catalogue.NotEvaluated(SignalDataPlane)
	}

	names := walkable(lists)
	if len(names) == 0 {
		// Nothing to walk is not the same as nothing written: the listing that
		// would have named the containers is its own signal, and if it failed
		// this signal cannot claim to have looked.
		return Catalogue.Absent(SignalDataPlane)
	}

	budget := collect.PrefixBudget{MaxCalls: maxCallsPerWalk, MaxTime: maxTimePerWalk}
	var newest time.Time
	var deepest string
	walked, partial := 0, false
	var failure error

	for _, name := range names {
		prefix, err := in.Clients.DataPlane.PrefixWalk(ctx, in.Target.ID, name, budget)
		if err != nil {
			// One container's refusal is the whole signal's unknown: the
			// containers this caller may not read are exactly the ones most
			// likely to hold the writes.
			failure = err
			break
		}
		walked++
		if !prefix.Complete {
			partial = true
		}
		if prefix.LastWrite.After(newest) {
			newest, deepest = prefix.LastWrite, prefix.Path
		}
	}

	switch {
	case failure != nil:
		return Catalogue.Failed(SignalDataPlane, failure)
	case newest.IsZero() && partial:
		return Catalogue.Unknown(SignalDataPlane, &verdict.Unknown{
			Code:    verdict.UnkPartial,
			Message: "the prefix walk ran out of its call or time budget before it reached a write"})
	case newest.IsZero():
		return Catalogue.Absent(SignalDataPlane)
	}

	details := map[string]any{
		"lastWrite":         signal.Timestamp(newest),
		"containersWalked":  walked,
		"partitionDepth":    strings.Count(deepest, "/") + 1,
		"withinFreshWindow": in.Cutoff.Sub(newest) <= freshnessWindow,
	}
	evidence := Catalogue.Present(SignalDataPlane, details)
	if in.Cutoff.Sub(newest) > freshnessWindow {
		// Older than the freshness window: a date, not activity.
		evidence.Tier = verdict.TierInfo
	}
	if partial {
		// The walk found a write and also ran short. The write stands; the
		// reader is told the sample was cut off.
		details["complete"] = false
	} else {
		details["complete"] = true
	}
	return evidence
}

// walkable picks the containers to sample, in a stable order so two runs over
// the same account walk the same ones.
func walkable(lists []childList) []string {
	var names []string
	for _, list := range lists {
		if list.name != "containers" {
			continue
		}
		for _, item := range list.items {
			names = append(names, item.Name)
		}
	}
	sort.Strings(names)
	if len(names) > maxWalkedContainers {
		names = names[:maxWalkedContainers]
	}
	return names
}
