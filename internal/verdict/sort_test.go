package verdict

import (
	"slices"
	"testing"
)

func TestPseudoOrder(t *testing.T) {
	ids := []string{"generic.never", "window.too-short-for-yes", "age.unknown", "required.missing:z", "required.missing:a", "age.inferred-only"}
	want := []string{"required.missing:a", "required.missing:z", "age.inferred-only", "age.unknown", "window.too-short-for-yes", "generic.never"}
	if !slices.Equal(sortedIDs(ids, nil), want) {
		t.Fatalf("wrong pseudo ordering: %v", ids)
	}
}
