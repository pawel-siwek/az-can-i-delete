package cordon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const oid = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"

func TestTheGrammarReadsWhatItAdmits(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  State
	}{
		{"pna", "v=1;m=pna;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Enabled;w=7",
			State{Mode: ModePNA, Since: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC), By: oid, Prior: "Enabled", WindowDays: 7}},
		{"pna behind a perimeter", "v=1;m=pna;t=2026-09-21T10:00:00Z;by=" + oid + ";p=SecuredByPerimeter;w=30",
			State{Mode: ModePNA, Since: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC), By: oid, Prior: "SecuredByPerimeter", WindowDays: 30}},
		{"stop with slots", "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=1;s=staging:Running,blue-2:Stopped",
			State{Mode: ModeStop, Since: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC), By: oid, Prior: "Running", WindowDays: 1,
				Slots: []Slot{{"staging", "Running"}, {"blue-2", "Stopped"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tc.want.Mode || !got.Since.Equal(tc.want.Since) || got.By != tc.want.By ||
				got.Prior != tc.want.Prior || got.WindowDays != tc.want.WindowDays || len(got.Slots) != len(tc.want.Slots) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got.Slots {
				if got.Slots[i] != tc.want.Slots[i] {
					t.Fatalf("slot %d: got %+v, want %+v", i, got.Slots[i], tc.want.Slots[i])
				}
			}
			again, err := got.Format()
			if err != nil || again != tc.value {
				t.Fatalf("round trip: %q, %v", again, err)
			}
		})
	}
}

func TestTheGrammarRefusesWhatItDoesNotAdmit(t *testing.T) {
	good := "v=1;m=pna;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Enabled;w=7"
	cases := map[string]string{
		"wrong order":             "v=1;t=2026-09-21T10:00:00Z;m=pna;by=" + oid + ";p=Enabled;w=7",
		"unknown key":             good + ";x=1",
		"missing key":             "v=1;m=pna;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Enabled",
		"version 2":               strings.Replace(good, "v=1", "v=2", 1),
		"unknown mode":            strings.Replace(good, "m=pna", "m=suspend", 1),
		"prior of the other mode": strings.Replace(good, "p=Enabled", "p=Running", 1),
		"stopped site prior":      "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Stopped;w=7",
		"disabled prior":          strings.Replace(good, "p=Enabled", "p=Disabled", 1),
		"upper-case oid":          strings.Replace(good, oid, strings.ToUpper(oid), 1),
		"offset timestamp":        strings.Replace(good, "10:00:00Z", "10:00:00+01:00", 1),
		"impossible date":         strings.Replace(good, "09-21", "02-30", 1),
		"window zero":             strings.Replace(good, "w=7", "w=0", 1),
		"window 31":               strings.Replace(good, "w=7", "w=31", 1),
		"window three digits":     strings.Replace(good, "w=7", "w=007", 1),
		"slots on pna":            good + ";s=a:Running",
		"five slots":              "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=7;s=a:Running,b:Running,c:Running,d:Running,e:Running",
		"slot state":              "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=7;s=a:Paused",
		"slot name":               "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=7;s=a_b:Running",
		"slot twice":              "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=7;s=a:Running,A:Stopped",
		"non-ASCII":               strings.Replace(good, "p=Enabled", "p=Enabléd", 1),
		"a resource id smuggled":  good + ";s=/subscriptions/x:Running",
		"longer than 200 bytes":   "v=1;m=stop;t=2026-09-21T10:00:00Z;by=" + oid + ";p=Running;w=7;s=" + strings.Repeat("a", 40) + ":Running," + strings.Repeat("b", 40) + ":Running," + strings.Repeat("c", 40) + ":Running",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(value); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Parse(%q) = %v, want ErrCorrupt", value, err)
			}
		})
	}
}

// The limit is on bytes, and it can refuse fewer than four slots: three long
// names already do, as SPEC section 4 warns.
func TestFormatRefusesAStateTooLargeToTag(t *testing.T) {
	state := State{Mode: ModeStop, Since: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC), By: oid, Prior: Running, WindowDays: 7,
		Slots: []Slot{{strings.Repeat("a", 40), Running}, {strings.Repeat("b", 40), Running}, {strings.Repeat("c", 40), Running}}}
	if _, err := state.Format(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Format() = %v, want a refusal", err)
	}
}

func TestRemainingNeverGoesNegative(t *testing.T) {
	state := State{Since: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), WindowDays: 7}
	if got := state.Remaining(time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)); got != 72*time.Hour {
		t.Fatalf("remaining = %v", got)
	}
	if got := state.Remaining(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); got != 0 {
		t.Fatalf("expired remaining = %v", got)
	}
}

func TestTheGateSpeaksTheSpecification(t *testing.T) {
	cases := []struct {
		resourceType string
		mode         Mode
		code         string
		message      string
	}{
		{"Microsoft.Storage/storageAccounts", ModePNA, "", ""},
		{"microsoft.web/SITES", ModeStop, "", ""},
		{"Microsoft.Compute/virtualMachines", "", CodeNotYetSupported,
			"cordon: Microsoft.Compute/virtualMachines is not supported in this version (planned: deallocate / stop / suspend). Use: az vm deallocate --ids <id>"},
		{"Microsoft.Network/networkInterfaces", "", CodeNotApplicable,
			"cordon: a detached NIC has no state to isolate; its verdict is structural. If it is attached, cordon the VM instead."},
		{"Microsoft.Compute/disks", "", CodeNotApplicable,
			"cordon: an unattached disk receives no traffic; nothing to isolate. Its verdict is structural (diskState, LastOwnershipUpdateTime)."},
		{"Microsoft.Web/serverfarms", "", CodeNotApplicable,
			"cordon: a plan with zero sites has no traffic; a plan with sites must not be deleted (BLOCKER). Cordon the sites instead."},
		{"Microsoft.Network/publicIPAddresses", "", CodeNotYetSupported, ""},
		{"Microsoft.Web/sites/slots", "", CodeUnsupportedType, "cordon: Microsoft.Web/sites/slots is not a supported type."},
		{"Microsoft.Sql/servers", "", CodeUnsupportedType, "cordon: Microsoft.Sql/servers is not a supported type."},
	}
	for _, tc := range cases {
		mode, refusal := Gate(tc.resourceType)
		if mode != tc.mode {
			t.Errorf("%s: mode %q, want %q", tc.resourceType, mode, tc.mode)
		}
		if tc.code == "" {
			if refusal != nil {
				t.Errorf("%s: refused: %v", tc.resourceType, refusal)
			}
			continue
		}
		if refusal == nil || refusal.Code != tc.code || refusal.Exit != 2 {
			t.Errorf("%s: refusal %+v, want code %s exit 2", tc.resourceType, refusal, tc.code)
			continue
		}
		if tc.message != "" && refusal.Message != tc.message {
			t.Errorf("%s:\n got %s\nwant %s", tc.resourceType, refusal.Message, tc.message)
		}
	}
}
