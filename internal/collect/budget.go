package collect

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
	"golang.org/x/sync/errgroup"
)

// The collection budgets bind REQUIREMENTS section 7 over the wider limits in
// the source research: six concurrent signals, fifteen Resource Graph calls per
// five seconds, twenty seconds per call and sixty seconds per run, with three
// bounded retries. Exhausting any of them is unknown(timeout|throttled|partial),
// never evidence that nothing was found.
const (
	MaxParallel     = 6
	GraphCalls      = 15
	GraphWindow     = 5 * time.Second
	CallTimeout     = 20 * time.Second
	RunTimeout      = 60 * time.Second
	MaxAttempts     = 3
	MaxGraphPage    = 1000
	MaxDeployments  = 200
	MaxMetricNames  = 20
	MaxSlots        = 4
	MaxDataPlaneDir = 5
)

// DataPlaneBudget is the opt-in per-container walk budget of SPEC section 3.2.
var DataPlaneBudget = PrefixBudget{MaxCalls: 12, MaxTime: 3 * time.Second}

// Clock isolates waiting so throttling and retry behaviour are testable without
// real delays. Decide stays pure; only collection is allowed to read a clock.
type Clock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// SystemClock waits on the real clock and respects cancellation.
func SystemClock() Clock {
	return Clock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return ctx.Err()
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

// Limiter is the fixed-window token bucket in front of Resource Graph. It
// delays rather than dropping calls; a caller that runs out of context gets a
// timeout unknown instead of a silently skipped query.
type Limiter struct {
	mu     sync.Mutex
	calls  int
	window time.Duration
	issued []time.Time
	clock  Clock
}

// NewLimiter builds a limiter of calls per window on the supplied clock.
func NewLimiter(calls int, window time.Duration, clock Clock) *Limiter {
	return &Limiter{calls: calls, window: window, clock: clock}
}

// NewGraphLimiter is the ARG limiter every collector must share.
func NewGraphLimiter(clock Clock) *Limiter { return NewLimiter(GraphCalls, GraphWindow, clock) }

// Wait blocks until the next call fits inside the window.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := l.reserve()
		if wait <= 0 {
			return nil
		}
		if err := l.clock.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// reserve records a call when one fits, or reports how long to wait for a slot.
func (l *Limiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	cutoff := now.Add(-l.window)
	l.issued = slices.DeleteFunc(l.issued, func(t time.Time) bool { return !t.After(cutoff) })
	if len(l.issued) < l.calls {
		l.issued = append(l.issued, now)
		return 0
	}
	return l.issued[0].Sub(cutoff)
}

// Retry runs call at most MaxAttempts times, honoring a server Retry-After and
// otherwise backing off exponentially. Only throttling, transient server
// failures and transport errors are retried; a 403 is an answer, not a blip.
func Retry(ctx context.Context, clock Clock, call func(ctx context.Context) error) error {
	var err error
	for attempt := 1; ; attempt++ {
		if err = call(ctx); err == nil {
			return nil
		}
		hint, retryable := RetryAfter(err)
		if !retryable || attempt >= MaxAttempts {
			return err
		}
		if hint <= 0 {
			hint = time.Duration(1<<(attempt-1)) * time.Second
		}
		if sleepErr := clock.Sleep(ctx, hint); sleepErr != nil {
			return err
		}
	}
}

// Signal is one unit of collection. Run returns the evidence it observed, or an
// error the gatherer converts into the signal's unknown. A signal that cannot
// run must still be reported, which is why Gather returns one outcome per ID.
type Signal struct {
	ID  string
	Run func(ctx context.Context) ([]verdict.Evidence, error)
}

// Outcome is a signal's result in the order the signal was declared. Exactly
// one of Evidence and Unknown is meaningful: a failed signal has no evidence.
type Outcome struct {
	ID       string
	Evidence []verdict.Evidence
	Unknown  *verdict.Unknown
}

// Gather runs signals with at most MaxParallel in flight, CallTimeout per
// signal and RunTimeout for the run. Results keep the declared order so a
// report never depends on scheduling. A signal that fails becomes
// unknown(code); one that never ran because the run budget ended becomes
// unknown(timeout). Only the deadlines read the clock, through the context.
func Gather(ctx context.Context, signals []Signal) []Outcome {
	runCtx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	outcomes := make([]Outcome, len(signals))
	group, groupCtx := errgroup.WithContext(runCtx)
	group.SetLimit(MaxParallel)
	for i, signal := range signals {
		outcomes[i] = Outcome{ID: signal.ID}
		group.Go(func() error {
			if groupCtx.Err() != nil {
				outcomes[i].Unknown = Classify(ErrBudgetExhausted)
				return nil
			}
			callCtx, callCancel := context.WithTimeout(groupCtx, CallTimeout)
			defer callCancel()
			evidence, err := signal.Run(callCtx)
			if err != nil {
				outcomes[i].Unknown = Classify(err)
				return nil
			}
			outcomes[i].Evidence = evidence
			return nil
		})
	}
	// No signal returns an error, so Wait only reports a cancelled run.
	_ = group.Wait()
	return outcomes
}
