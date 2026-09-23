package cordon

import (
	"context"
	"errors"
)

// Writer is the only boundary in this repository that changes Azure. It is
// not one of the five collection boundaries and no analyzer can reach it:
// assessment reads (ADR-0005), and a cordon is a separate, confirmed act that
// holds this interface for as long as it runs and no longer.
//
// Every method that starts a long-running operation waits for it to reach a
// terminal state. One that does not finish in time returns ErrStillRunning,
// which is neither success nor failure: nothing is reverted blindly on a
// timeout (SPEC appendix E section 6.3 step 4).
type Writer interface {
	// Principal names the signed-in identity the cordon is recorded under.
	Principal(ctx context.Context) (Principal, error)
	// Patch sends a JSON merge body to a resource. No etag: the storage
	// API has none to offer, and claiming one would be a lie.
	Patch(ctx context.Context, resourceID, apiVersion string, body map[string]any) error
	// Action POSTs to resourceID/action, such as a site's stop or start.
	Action(ctx context.Context, resourceID, action, apiVersion string) error
	// Tags merges or deletes tags on a resource through the tags resource,
	// which leaves every other tag alone.
	Tags(ctx context.Context, resourceID string, operation TagOperation, tags map[string]string) error
	// CheckPolicy asks Azure Policy what it would do to a resource body. It
	// changes nothing, but it is a POST, and it is only ever asked on the
	// cordon path.
	CheckPolicy(ctx context.Context, check PolicyCheck) (PolicyResult, error)
}

// Principal is the object id of the caller, and the application id when the
// caller is an application.
type Principal struct {
	ObjectID string
	AppID    string
}

// TagOperation is the tags API's patch operation.
type TagOperation string

// The two operations a cordon uses.
const (
	TagMerge  TagOperation = "Merge"
	TagDelete TagOperation = "Delete"
)

// PolicyCheck is one checkPolicyRestrictions question: what would policy do to
// this body, deployed at this scope.
type PolicyCheck struct {
	// Scope is the resource group the resource lives in.
	Scope      string
	Content    map[string]any
	APIVersion string
	// Field is the policy alias the cordon flips, or empty when the type has
	// none and only the content evaluation can answer.
	Field string
}

// PolicyResult is what policy would do. Restricted means a Deny, or a Modify
// that would change the flipped field back.
type PolicyResult struct {
	Restricted bool
	Effects    []string
}

// ErrStillRunning is a long-running operation that did not finish inside its
// deadline. The state is unknown, so it is reported as such and never undone.
var ErrStillRunning = errors.New("the operation is still running")
