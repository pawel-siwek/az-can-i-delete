package collect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Failure is a service or transport failure from one client call. Adapters
// report what Azure actually said; this package decides what that means for a
// signal. RetryAfter is the honored server hint, zero when absent.
type Failure struct {
	StatusCode int
	ErrorCode  string
	Message    string
	RetryAfter time.Duration
	Err        error
}

// Error keeps the status and service error code visible in logs and tests.
func (f *Failure) Error() string {
	switch {
	case f.StatusCode != 0 && f.ErrorCode != "":
		return fmt.Sprintf("azure %d %s: %s", f.StatusCode, f.ErrorCode, f.Message)
	case f.StatusCode != 0:
		return fmt.Sprintf("azure %d: %s", f.StatusCode, f.Message)
	case f.Err != nil:
		return f.Err.Error()
	default:
		return f.Message
	}
}

// Unwrap exposes a transport error so callers can test for net errors.
func (f *Failure) Unwrap() error { return f.Err }

// NotFound reports a 404, which the target GET turns into exit 3 and every
// dependency lookup turns into unknown(dependency) rather than absence.
func NotFound(err error) bool {
	var failure *Failure
	return errors.As(err, &failure) && failure.StatusCode == http.StatusNotFound
}

// RetryAfter returns the server's honored retry hint and whether the call may
// be retried at all: only throttling and transient server failures may be.
func RetryAfter(err error) (time.Duration, bool) {
	var failure *Failure
	if !errors.As(err, &failure) {
		return 0, transportRetryable(err)
	}
	switch {
	case failure.StatusCode == http.StatusTooManyRequests,
		failure.StatusCode >= 500 && failure.StatusCode <= 599:
		return failure.RetryAfter, true
	case failure.StatusCode != 0:
		return 0, false
	default:
		return 0, transportRetryable(failure.Err)
	}
}

func transportRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// Classify turns any collection failure into the unknown a signal must carry.
// It never returns nil for a non-nil error and never reports absence: an
// unreadable dependency stays unknown, which is what keeps `yes` unreachable.
//
// The message is tool-owned and written here as a literal. Azure's own error
// text is never copied into it: it is free-form, it is attacker-influenceable
// through resource names, and it is the one string in a failure that nobody
// has read before it reaches a report. internal/conformance holds every
// reason in the repository to being a literal so that stays true.
func Classify(err error) *verdict.Unknown {
	if err == nil {
		return nil
	}
	unknown := classify(err)
	var failure *Failure
	if errors.As(err, &failure) {
		unknown.HTTPStatus, unknown.ErrorCode = failure.StatusCode, failure.ErrorCode
	}
	return unknown
}

// classify names the failure. Each arm returns its own reason rather than
// deriving one, so the code says what kind of failure it was and the reason
// says which one: "the request was rejected" and "the service failed to
// answer" are both transient and point at different problems.
func classify(err error) *verdict.Unknown {
	var failure *Failure
	if !errors.As(err, &failure) {
		return classifyTransport(err)
	}
	switch {
	case failure.StatusCode == http.StatusUnauthorized:
		return &verdict.Unknown{Code: verdict.UnkAuth, Message: "the credential was rejected"}
	case failure.StatusCode == http.StatusForbidden:
		return &verdict.Unknown{Code: verdict.UnkPermission, Message: "the caller is not authorized to read this"}
	case failure.StatusCode == http.StatusNotFound:
		return &verdict.Unknown{Code: verdict.UnkDependency, Message: "the referenced resource could not be read"}
	case failure.StatusCode == http.StatusRequestTimeout,
		failure.StatusCode == http.StatusGatewayTimeout:
		return &verdict.Unknown{Code: verdict.UnkTimeout, Message: "the service did not answer in time"}
	case failure.StatusCode == http.StatusTooManyRequests:
		return &verdict.Unknown{Code: verdict.UnkThrottled, Message: "the request budget was exhausted by throttling"}
	case failure.StatusCode >= 500 && failure.StatusCode <= 599:
		return &verdict.Unknown{Code: verdict.UnkTransient, Message: "the service failed to answer"}
	case unsupported(failure):
		return &verdict.Unknown{Code: verdict.UnkUnsupported, Message: "this check is not supported for this resource or api-version"}
	case failure.StatusCode >= 400 && failure.StatusCode <= 499:
		return &verdict.Unknown{Code: verdict.UnkTransient, Message: "the request was rejected"}
	case failure.Err != nil:
		return classifyTransport(failure.Err)
	}
	return &verdict.Unknown{Code: verdict.UnkTransient, Message: "collection failed"}
}

func classifyTransport(err error) *verdict.Unknown {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &verdict.Unknown{Code: verdict.UnkTimeout, Message: "the call exceeded its budget"}
	case errors.Is(err, ErrBudgetExhausted):
		return &verdict.Unknown{Code: verdict.UnkTimeout, Message: "the run budget was exhausted before this call"}
	case errors.Is(err, ErrTruncated):
		return &verdict.Unknown{Code: verdict.UnkPartial, Message: "the answer was incomplete"}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return &verdict.Unknown{Code: verdict.UnkTimeout, Message: "the call exceeded its budget"}
		}
		return &verdict.Unknown{Code: verdict.UnkNetwork, Message: "the service could not be reached"}
	}
	return &verdict.Unknown{Code: verdict.UnkTransient, Message: "collection failed"}
}

// Azure reports an unsupported api-version, operation or feature as a 400 with
// a documented code; only those become unknown(unsupported) so that a genuine
// bad request is not disguised as an unimplemented check.
func unsupported(failure *Failure) bool {
	switch strings.ToLower(failure.ErrorCode) {
	case "nosupportedapiversion", "invalidapiversionparameter", "unsupportedoperation",
		"featurenotsupported", "notsupported", "operationnotallowed":
		return true
	default:
		return false
	}
}

// ErrBudgetExhausted is returned when the run budget ended before a call ran.
var ErrBudgetExhausted = errors.New("run budget exhausted")

// ErrTruncated marks an incomplete listing or a saturated response cap.
var ErrTruncated = errors.New("result truncated")
