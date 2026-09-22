package storage

import (
	"context"

	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// metricGroup turns the five metric calls into the activity and silence
// signals. Live activity is judged over the requested window; silence is
// judged over the effective one, which is the requested window bounded by how
// long the account has demonstrably existed.
type metricGroup struct{}

func (metricGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		configuration, defender := readDefender(ctx, in)
		observed := collectMetrics(ctx, in)
		requested := summarize(observed.transactions, in.Requested)
		effective := in.effective()
		quiet := summarize(observed.transactions, effective)

		live := reads(in, requested, observed, defender)
		evidence := []verdict.Evidence{
			configuration,
			anonymous(in, requested, observed),
			writes(in, requested, observed),
			live,
			lowVolumeReads(in, requested, live),
			smb(in, requested),
		}
		evidence = append(evidence, queue(in, requested)...)
		evidence = append(evidence, counts(in, observed)...)
		evidence = append(evidence,
			defenderShaped(in, requested, defender),
			system(in, requested),
			silence(in, quiet, effective, observed))
		return evidence, nil
	}
}

// defenderState is what the read rules need to know about the scanner. Each
// field is tri-state: unknown configuration must never be read as "off".
type defenderState struct {
	Enabled  bool
	OnUpload bool
	SDD      bool
	Known    bool
}

// readDefender reads the Defender for Storage settings once, and returns both
// the informational signal and the state the read rules need. Configuration
// that could not be read stays unknown: it never collapses into "the scanner
// could not have run".
func readDefender(ctx context.Context, in Input) (verdict.Evidence, defenderState) {
	evidence := defenderConfiguration(ctx, in)
	switch evidence.Status {
	case verdict.StatusPresent:
		enabled, _ := evidence.Details["enabled"].(bool)
		upload, _ := evidence.Details["onUpload"].(bool)
		sdd, _ := evidence.Details["sensitiveDataDiscovery"].(bool)
		return evidence, defenderState{Enabled: enabled, OnUpload: upload, SDD: sdd, Known: true}
	case verdict.StatusAbsent:
		return evidence, defenderState{Known: true}
	default:
		return evidence, defenderState{}
	}
}

// anonymous reports successful anonymous requests: somebody on the internet
// is reading this account without credentials.
func anonymous(in Input, requested totals, observed observations) verdict.Evidence {
	if err, failed := observed.failures["M2"]; failed {
		return Catalogue.Failed(SignalAnonymous, err)
	}
	if requested.AnonymousOK == 0 {
		return signal.Windowed(Catalogue.Absent(SignalAnonymous), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Present(SignalAnonymous,
		map[string]any{"requestCount": requested.AnonymousOK}), in.Cutoff, in.Requested.Days)
}

// writes applies the amended write rule: ten writes spread over two days, or a
// thousand in one, is somebody using the account rather than a stray call.
func writes(in Input, requested totals, observed observations) verdict.Evidence {
	if err, failed := observed.failures["M1"]; failed {
		return Catalogue.Failed(SignalWrites, err)
	}
	live := (requested.WritePrimeSum >= WriteFloor && requested.WritePrimeDays >= WriteFloorDays) ||
		requested.WritePrimeMax >= WriteSingleDay
	if !live {
		return signal.Windowed(Catalogue.Absent(SignalWrites), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Present(SignalWrites, map[string]any{
		"writeCount": requested.WritePrimeSum, "writeDays": requested.WritePrimeDays}),
		in.Cutoff, in.Requested.Days)
}

// reads applies the amended read rule and the Defender carve-out: when the
// configured scanner could have run and every successful read was
// Entra-authenticated, the reads are design intent rather than live use,
// because the scanner's reads cannot be separated from a person's.
func reads(in Input, requested totals, observed observations, defender defenderState) verdict.Evidence {
	if err, failed := observed.failures["M1"]; failed {
		return Catalogue.Failed(SignalReads, err)
	}
	egress := egressMiB(observed.egress, in.Requested)
	volume := requested.ReadDays >= ReadDays && (egress >= ReadEgressMiB || requested.ReadSum >= ReadFloor)
	if !volume {
		return signal.Windowed(Catalogue.Absent(SignalReads), in.Cutoff, in.Requested.Days)
	}
	if scannerCouldRun(defender, requested) == yes && oauthOnly(requested) {
		// The reads may all be the scanner's. They are reported as intent by
		// the Defender signal instead, and never as live use.
		return signal.Windowed(Catalogue.Absent(SignalReads), in.Cutoff, in.Requested.Days)
	}
	if scannerCouldRun(defender, requested) == unknown && oauthOnly(requested) {
		return Catalogue.Unknown(SignalReads, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "the Defender scanner configuration could not be read, so these reads cannot be attributed"})
	}
	return signal.Windowed(Catalogue.Present(SignalReads, map[string]any{
		"readCount": requested.ReadSum, "readDays": requested.ReadDays, "egressMiB": egress}),
		in.Cutoff, in.Requested.Days)
}

// triState is the answer to a question whose inputs may be unreadable.
type triState int

// The three answers. Unknown never collapses into no.
const (
	no triState = iota
	yes
	unknown
)

// scannerCouldRun is the amended predicate: on-upload scanning only runs when
// something was uploaded, while sensitive data discovery runs on its own.
func scannerCouldRun(defender defenderState, requested totals) triState {
	if !defender.Known {
		return unknown
	}
	if !defender.Enabled {
		return no
	}
	if defender.SDD || (defender.OnUpload && requested.WritePrimeSum > 0) {
		return yes
	}
	return no
}

// oauthOnly reports whether every successful user request was
// Entra-authenticated, which is the shape a scanner's reads have.
func oauthOnly(requested totals) bool {
	return requested.NonOAuthReads == 0 && requested.OAuthReads > 0
}

// defenderShaped reports reads that cannot be attributed. The per-operation
// shape analysis that would separate the scanner from real readers is not
// implemented; this signal says so rather than guessing.
func defenderShaped(in Input, requested totals, defender defenderState) verdict.Evidence {
	if scannerCouldRun(defender, requested) == yes && oauthOnly(requested) {
		return signal.Windowed(Catalogue.Present(SignalDefenderShaped, map[string]any{
			"readCount": requested.OAuthReads}), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Absent(SignalDefenderShaped), in.Cutoff, in.Requested.Days)
}

// queue applies the polling rule: a consumer hammering an empty queue is a
// deployed system, while an occasional poll is only intent.
func queue(in Input, requested totals) []verdict.Evidence {
	busyDays, total := 0, float64(0)
	for _, value := range requested.PollingPerDay {
		total += value
		if value >= PollingLivePerDay {
			busyDays++
		}
	}
	live := Catalogue.Absent(SignalQueue)
	low := Catalogue.Absent(SignalQueueLow)
	switch {
	case busyDays >= PollingLiveDays:
		live = Catalogue.Present(SignalQueue, map[string]any{"pollCount": total, "pollDays": busyDays})
	case total > 0:
		low = Catalogue.Present(SignalQueueLow, map[string]any{
			"pollCount": total, "pollDays": len(requested.PollingPerDay)})
	}
	return []verdict.Evidence{
		signal.Windowed(live, in.Cutoff, in.Requested.Days),
		signal.Windowed(low, in.Cutoff, in.Requested.Days),
	}
}

// counts reports growth in the object counters, and the silence signal that
// says they did not grow. A growing count is data arriving whatever the
// transaction metrics say.
func counts(in Input, observed observations) []verdict.Evidence {
	if err, failed := observed.failures["M4"]; failed {
		return []verdict.Evidence{
			Catalogue.Failed(SignalCountDelta, err),
			Catalogue.Failed(SignalCountSilence, err),
		}
	}
	effective := in.effective()
	growthDays, delta := 0, float64(0)
	for _, records := range observed.counts {
		days, grown := countIncreaseDays(records, in.Requested)
		growthDays += days
		delta += grown
	}
	quietDays := 0
	for _, records := range observed.counts {
		days, _ := countIncreaseDays(records, effective)
		quietDays += days
	}
	growth := signal.Windowed(Catalogue.Absent(SignalCountDelta), in.Cutoff, in.Requested.Days)
	if growthDays >= CountDeltaDays {
		growth = signal.Windowed(Catalogue.Present(SignalCountDelta,
			map[string]any{"growthDays": growthDays, "objectDelta": delta}), in.Cutoff, in.Requested.Days)
	}
	var quiet verdict.Evidence
	switch {
	case quietDays > 0:
		quiet = signal.Windowed(Catalogue.Absent(SignalCountSilence), in.Cutoff, effective.Days)
	case effective.Days == 0:
		quiet = Catalogue.Unknown(SignalCountSilence, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the account's age leaves no effective window to observe"})
	default:
		quiet = signal.Windowed(Catalogue.Present(SignalCountSilence,
			map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
	}
	return []verdict.Evidence{growth, quiet}
}

// smb reports a client with a file share mounted.
func smb(in Input, requested totals) verdict.Evidence {
	if requested.SMBSessions == 0 {
		return signal.Windowed(Catalogue.Absent(SignalSMB), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Present(SignalSMB,
		map[string]any{"sessionCount": requested.SMBSessions}), in.Cutoff, in.Requested.Days)
}

// system reports the platform's own transactions, which are information: they
// are not somebody using the account.
func system(in Input, requested totals) verdict.Evidence {
	if requested.SystemSum == 0 {
		return signal.Windowed(Catalogue.Absent(SignalSystem), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Present(SignalSystem,
		map[string]any{"transactionCount": requested.SystemSum}), in.Cutoff, in.Requested.Days)
}

// silence is the Required signal: no user transaction of any class over the
// effective window. It can only be established when the transaction metric
// answered and every operation in it could be classified — an operation this
// tool does not recognize is activity it does not understand, not silence.
func silence(in Input, quiet totals, effective verdict.Window, observed observations) verdict.Evidence {
	if err, failed := observed.failures["M1"]; failed {
		return Catalogue.Failed(SignalSilence, err)
	}
	switch {
	case effective.Days == 0:
		return Catalogue.Unknown(SignalSilence, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the account's age leaves no effective window to observe"})
	case quiet.UnclassifiedSum > 0:
		return Catalogue.Unknown(SignalSilence, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "the account served operations this version cannot classify, such as NFS"})
	case quiet.ActivitySum > 0:
		return signal.Windowed(Catalogue.Absent(SignalSilence), in.Cutoff, effective.Days)
	default:
		return signal.Windowed(Catalogue.Present(SignalSilence,
			map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
	}
}

// lowVolumeReads reports reads below the live threshold: somebody or something
// touches the account, but not enough to call it in use.
func lowVolumeReads(in Input, requested totals, live verdict.Evidence) verdict.Evidence {
	if requested.ReadSum > 0 && live.Status != verdict.StatusPresent {
		return signal.Windowed(Catalogue.Present(SignalLowReads, map[string]any{
			"readCount": requested.ReadSum, "readDays": requested.ReadDays}), in.Cutoff, in.Requested.Days)
	}
	return signal.Windowed(Catalogue.Absent(SignalLowReads), in.Cutoff, in.Requested.Days)
}
