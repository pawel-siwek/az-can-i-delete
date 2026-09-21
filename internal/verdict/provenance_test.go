package verdict_test

import (
	"slices"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The fixed ARG signal IDs, tiers and criticality below come from architect-3
// sections 5.0/5.1, not arbitrary unknowns invented to trigger a verdict.
// This checks fixture normalization, not an analyzer or collection path.
func TestSourceDerivedFixtureMappings(t *testing.T) {
	arg := map[string]struct {
		tier     verdict.Tier
		critical bool
	}{
		"generic.rg.managedby":              {verdict.TierHardDependency, true},
		"generic.dns.records":               {verdict.TierHardDependency, true},
		"generic.tags.hidden-link":          {verdict.TierHardDependency, false},
		"generic.tags.hidden-link-dangling": {verdict.TierInfo, false},
		"generic.advisor":                   {verdict.TierObservedIdle, false},
		"storage.netacl.resource-instances": {verdict.TierHardDependency, true},
		"storage.bootdiag.vms":              {verdict.TierHardDependency, true},
		"storage.flowlogs":                  {verdict.TierHardDependency, true},
		"storage.backup.items":              {verdict.TierHardDependency, true},
		"storage.reverse.generic-has":       {verdict.TierHardDependency, true},
		"storage.vmext.diagnostics":         {verdict.TierHardDependency, true},
	}
	for _, f := range loadFixtures(t) {
		switch f.Number {
		case 21, 57, 58:
			seen := make(map[string]bool)
			for _, e := range f.Input.Evidence {
				if e.Status != verdict.StatusUnknown {
					continue
				}
				want, ok := arg[e.ID]
				if !ok || want.tier != e.Tier || want.critical != e.Critical ||
					e.Unknown == nil || e.Unknown.Code != verdict.UnkPermission {
					t.Errorf("row%d: unknown signal differs from source catalogue: %+v", f.Number, e)
				}
				seen[e.ID] = true
			}
			for id := range arg {
				if !seen[id] {
					t.Errorf("row%d: missing applicable ARG observation %s", f.Number, id)
				}
			}
			if len(f.Conventions) == 0 || f.Expect.CriticalUnknown != 8 {
				t.Errorf("row%d: missing bounded-normalization disclosure/count", f.Number)
			}
		case 16, 44:
			got, err := verdict.Evaluate(f.Input)
			want := []string{"site.metrics.function-executions", "site.metrics.silence"}
			if err != nil || got.Coverage.CriticalUnknown != 2 || !slices.Equal(got.Unknowns, want) {
				t.Errorf("row%d: must retain exactly two tier-ordered critical unknowns: %+v, %v", f.Number, got, err)
			}
		case 49:
			if f.Input.Requested.Days != 90 || f.Expect.Effective.Days != 45 || verdict.DefaultRequestedDays != 30 {
				t.Error("row49 historical window must not alter product default30")
			}
		}
	}
}
