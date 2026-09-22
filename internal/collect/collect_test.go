package collect_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// testClock records what a caller would have waited for without waiting.
type testClock struct {
	mu     sync.Mutex
	now    time.Time
	slept  []time.Duration
	failAt int
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC), failAt: -1}
}

func (c *testClock) clock() collect.Clock {
	return collect.Clock{
		Now: func() time.Time {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.now
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.failAt == len(c.slept) {
				return context.DeadlineExceeded
			}
			c.slept = append(c.slept, d)
			c.now = c.now.Add(d)
			return ctx.Err()
		},
	}
}

func (c *testClock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.slept)
}

type timeoutError struct{}

func (timeoutError) Error() string { return "i/o timeout" }
func (timeoutError) Timeout() bool { return true }
func (timeoutError) Temporary() bool {
	return true
}

func TestClassifyNeverInventsAbsence(t *testing.T) {
	var netTimeout net.Error = timeoutError{}
	cases := []struct {
		name string
		err  error
		want verdict.UnknownCode
	}{
		{"credential-rejected", &collect.Failure{StatusCode: 401}, verdict.UnkAuth},
		{"forbidden", &collect.Failure{StatusCode: 403}, verdict.UnkPermission},
		{"dependency-gone", &collect.Failure{StatusCode: 404}, verdict.UnkDependency},
		{"request-timeout", &collect.Failure{StatusCode: 408}, verdict.UnkTimeout},
		{"gateway-timeout", &collect.Failure{StatusCode: 504}, verdict.UnkTimeout},
		{"throttled", &collect.Failure{StatusCode: 429}, verdict.UnkThrottled},
		{"server-error", &collect.Failure{StatusCode: 503}, verdict.UnkTransient},
		{"unsupported-api-version", &collect.Failure{StatusCode: 400, ErrorCode: "NoSupportedApiVersion"}, verdict.UnkUnsupported},
		{"bad-request", &collect.Failure{StatusCode: 400, ErrorCode: "InvalidResourceId"}, verdict.UnkTransient},
		{"wrapped-failure", fmt.Errorf("locks: %w", &collect.Failure{StatusCode: 403}), verdict.UnkPermission},
		{"transport-timeout", &collect.Failure{Err: netTimeout}, verdict.UnkTimeout},
		{"unreachable", &collect.Failure{Err: net.UnknownNetworkError("tcp")}, verdict.UnkNetwork},
		{"deadline", context.DeadlineExceeded, verdict.UnkTimeout},
		{"run-budget", collect.ErrBudgetExhausted, verdict.UnkTimeout},
		{"truncated", collect.ErrTruncated, verdict.UnkPartial},
		{"unclassified", errors.New("boom"), verdict.UnkTransient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := collect.Classify(c.err)
			if got == nil || got.Code != c.want {
				t.Fatalf("classify(%v) = %+v, want %s", c.err, got, c.want)
			}
			if got.Message == "" {
				t.Error("every unknown must carry a tool-owned explanation")
			}
		})
	}
	if collect.Classify(nil) != nil {
		t.Error("a successful call has no unknown")
	}
}

func TestClassifyKeepsServiceStatusAndCode(t *testing.T) {
	got := collect.Classify(&collect.Failure{StatusCode: 403, ErrorCode: "AuthorizationFailed", Message: "forbidden"})
	if got.HTTPStatus != 403 || got.ErrorCode != "AuthorizationFailed" {
		t.Fatalf("status and service code must survive classification: %+v", got)
	}
	if got.Message == "forbidden" {
		t.Error("Azure free-form text must not become the unknown message")
	}
}

func TestNotFoundAndRetryability(t *testing.T) {
	if !collect.NotFound(fmt.Errorf("get: %w", &collect.Failure{StatusCode: 404})) {
		t.Error("404 must be recognizable through wrapping")
	}
	if collect.NotFound(&collect.Failure{StatusCode: 403}) {
		t.Error("403 is not a missing resource")
	}
	hint, retryable := collect.RetryAfter(&collect.Failure{StatusCode: 429, RetryAfter: 7 * time.Second})
	if !retryable || hint != 7*time.Second {
		t.Fatalf("throttling must be retried after the server hint: %v %v", hint, retryable)
	}
	if _, retryable := collect.RetryAfter(&collect.Failure{StatusCode: 403}); retryable {
		t.Error("an authorization answer must not be retried")
	}
	if _, retryable := collect.RetryAfter(context.Canceled); retryable {
		t.Error("a cancelled run must not be retried")
	}
}

func TestRetryHonorsServerHintAndAttemptCap(t *testing.T) {
	clock := newTestClock()
	var attempts int
	err := collect.Retry(context.Background(), clock.clock(), func(context.Context) error {
		attempts++
		return &collect.Failure{StatusCode: 429, RetryAfter: 2 * time.Second}
	})
	if attempts != collect.MaxAttempts || err == nil {
		t.Fatalf("throttled call ran %d times, want %d bounded attempts (err %v)", attempts, collect.MaxAttempts, err)
	}
	if want := []time.Duration{2 * time.Second, 2 * time.Second}; !slices.Equal(clock.waits(), want) {
		t.Errorf("waits = %v, want the server hint before each retry %v", clock.waits(), want)
	}
}

func TestRetryBacksOffAndStopsOnAnswer(t *testing.T) {
	clock := newTestClock()
	var attempts int
	err := collect.Retry(context.Background(), clock.clock(), func(context.Context) error {
		attempts++
		if attempts == 1 {
			return &collect.Failure{StatusCode: 500}
		}
		return nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("a transient failure must be retried once and then succeed: %d %v", attempts, err)
	}
	if want := []time.Duration{time.Second}; !slices.Equal(clock.waits(), want) {
		t.Errorf("waits = %v, want exponential backoff %v", clock.waits(), want)
	}
	attempts = 0
	if err := collect.Retry(context.Background(), clock.clock(), func(context.Context) error {
		attempts++
		return &collect.Failure{StatusCode: 403}
	}); err == nil || attempts != 1 {
		t.Fatalf("a permission answer must not be retried: %d %v", attempts, err)
	}
}

func TestGraphLimiterDelaysRatherThanDroppingCalls(t *testing.T) {
	clock := newTestClock()
	limiter := collect.NewGraphLimiter(clock.clock())
	for i := range collect.GraphCalls {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatalf("call %d inside the window must not wait: %v", i, err)
		}
	}
	if len(clock.waits()) != 0 {
		t.Fatalf("the first %d calls must not be delayed: %v", collect.GraphCalls, clock.waits())
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("the next call must be delayed, not refused: %v", err)
	}
	if want := []time.Duration{collect.GraphWindow}; !slices.Equal(clock.waits(), want) {
		t.Errorf("waits = %v, want one full window %v", clock.waits(), want)
	}
}

func TestLimiterReportsCancellationInsteadOfSkipping(t *testing.T) {
	clock := newTestClock()
	clock.failAt = 0
	limiter := collect.NewLimiter(1, collect.GraphWindow, clock.clock())
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Wait(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a limiter that cannot wait must report it: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := collect.NewGraphLimiter(clock.clock()).Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must not be granted a slot: %v", err)
	}
}

func TestGatherKeepsDeclaredOrderAndBoundsParallelism(t *testing.T) {
	const signals = 30
	var inFlight, peak atomic.Int64
	var declared []collect.Signal
	release := make(chan struct{})
	for i := range signals {
		declared = append(declared, collect.Signal{
			ID: fmt.Sprintf("generic.signal.%02d", i),
			Run: func(context.Context) ([]verdict.Evidence, error) {
				current := inFlight.Add(1)
				for {
					top := peak.Load()
					if current <= top || peak.CompareAndSwap(top, current) {
						break
					}
				}
				<-release
				inFlight.Add(-1)
				return []verdict.Evidence{{ID: fmt.Sprintf("generic.signal.%02d", i)}}, nil
			},
		})
	}
	done := make(chan []collect.Outcome)
	go func() { done <- collect.Gather(context.Background(), declared) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	outcomes := <-done
	if len(outcomes) != signals {
		t.Fatalf("every declared signal must be reported: %d", len(outcomes))
	}
	for i, outcome := range outcomes {
		want := fmt.Sprintf("generic.signal.%02d", i)
		if outcome.ID != want || len(outcome.Evidence) != 1 || outcome.Evidence[0].ID != want {
			t.Fatalf("outcome %d = %+v, want the declared order", i, outcome)
		}
	}
	if peak.Load() > collect.MaxParallel {
		t.Errorf("peak parallelism %d exceeds the budget of %d", peak.Load(), collect.MaxParallel)
	}
}

func TestGatherTurnsFailuresIntoUnknownsAndKeepsOtherSignals(t *testing.T) {
	outcomes := collect.Gather(context.Background(), []collect.Signal{
		{ID: "generic.lock.cannotdelete", Run: func(context.Context) ([]verdict.Evidence, error) {
			return nil, &collect.Failure{StatusCode: 403}
		}},
		{ID: "generic.arg.visible", Run: func(context.Context) ([]verdict.Evidence, error) {
			return []verdict.Evidence{{ID: "generic.arg.visible", Status: verdict.StatusAbsent}}, nil
		}},
		{ID: "generic.advisor", Run: func(context.Context) ([]verdict.Evidence, error) {
			return nil, nil
		}},
	})
	if outcomes[0].Unknown == nil || outcomes[0].Unknown.Code != verdict.UnkPermission || outcomes[0].Evidence != nil {
		t.Fatalf("a failed signal must be unknown and carry no evidence: %+v", outcomes[0])
	}
	if outcomes[1].Unknown != nil || outcomes[1].Evidence[0].Status != verdict.StatusAbsent {
		t.Fatalf("one failure must not suppress another signal: %+v", outcomes[1])
	}
	if outcomes[2].Unknown != nil || len(outcomes[2].Evidence) != 0 {
		t.Fatalf("a signal with nothing to report is not a failure: %+v", outcomes[2])
	}
}

func TestGatherReportsSignalsTheBudgetNeverReached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcomes := collect.Gather(ctx, []collect.Signal{{ID: "generic.dns.records",
		Run: func(context.Context) ([]verdict.Evidence, error) {
			t.Error("a signal must not run after the run budget ended")
			return nil, nil
		}}})
	if outcomes[0].Unknown == nil || outcomes[0].Unknown.Code != verdict.UnkTimeout {
		t.Fatalf("an unreached signal must still be reported: %+v", outcomes[0])
	}
}
