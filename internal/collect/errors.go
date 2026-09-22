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
// Message is tool-owned; no Azure free-form text is copied into it.
func Classify(err error) *verdict.Unknown {
	if err == nil {
		return nil
	}
	unknown := &verdict.Unknown{Code: verdict.UnkTransient, Message: "collection failed"}
	var failure *Failure
	if !errors.As(err, &failure) {
		unknown.Code, unknown.Message = classifyTransport(err)
		return unknown
	}
	unknown.HTTPStatus, unknown.ErrorCode = failure.StatusCode, failure.ErrorCode
	switch {
	case failure.StatusCode == http.StatusUnauthorized:
		unknown.Code, unknown.Message = verdict.UnkAuth, "the credential was rejected"
	case failure.StatusCode == http.StatusForbidden:
		unknown.Code, unknown.Message = verdict.UnkPermission, "the caller is not authorized to read this"
	case failure.StatusCode == http.StatusNotFound:
		unknown.Code, unknown.Message = verdict.UnkDependency, "the referenced resource could not be read"
	case failure.StatusCode == http.StatusRequestTimeout,
		failure.StatusCode == http.StatusGatewayTimeout:
		unknown.Code, unknown.Message = verdict.UnkTimeout, "the service did not answer in time"
	case failure.StatusCode == http.StatusTooManyRequests:
		unknown.Code, unknown.Message = verdict.UnkThrottled, "the request budget was exhausted by throttling"
	case failure.StatusCode >= 500 && failure.StatusCode <= 599:
		unknown.Code, unknown.Message = verdict.UnkTransient, "the service failed to answer"
	case unsupported(failure):
		unknown.Code, unknown.Message = verdict.UnkUnsupported, "this check is not supported for this resource or api-version"
	case failure.StatusCode >= 400 && failure.StatusCode <= 499:
		unknown.Code, unknown.Message = verdict.UnkTransient, "the request was rejected"
	case failure.Err != nil:
		unknown.Code, unknown.Message = classifyTransport(failure.Err)
	}
	return unknown
}

func classifyTransport(err error) (verdict.UnknownCode, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return verdict.UnkTimeout, "the call exceeded its budget"
	case errors.Is(err, ErrBudgetExhausted):
		return verdict.UnkTimeout, "the run budget was exhausted before this call"
	case errors.Is(err, ErrTruncated):
		return verdict.UnkPartial, "the answer was incomplete"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return verdict.UnkTimeout, "the call exceeded its budget"
		}
		return verdict.UnkNetwork, "the service could not be reached"
	}
	return verdict.UnkTransient, "collection failed"
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
