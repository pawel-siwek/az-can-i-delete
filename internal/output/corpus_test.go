package output

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

type deceptiveNumber int

func (deceptiveNumber) MarshalJSON() ([]byte, error) {
	return []byte(`"PROVIDER-INSTRUCTION"`), nil
}

func TestCustomNumericMarshalerCannotBypassPolicy(t *testing.T) {
	in, cfg := sample(), config()
	e := &in.Assessment.Evidence[0]
	e.Details = map[string]any{"count": deceptiveNumber(7)}
	cfg.Policies = map[string]SignalPolicy{e.ID: {Details: map[string]DetailPolicy{"count": {Kind: Number}}}}
	text := encoded(t, build(t, in, cfg))
	if strings.Contains(text, "PROVIDER-INSTRUCTION") || !strings.Contains(text, `"count":7`) {
		t.Fatal("custom marshaler crossed numeric boundary")
	}
}

func TestASCIIOnlyUnderUntrusted(t *testing.T) {
	in := sample()
	in.Metadata.Name = "ASCII-NAME-INSTRUCTION"
	in.Metadata.ResourceGroup = "ASCII-GROUP-INSTRUCTION"
	in.Metadata.Callers = []string{"ASCII-CALLER-INSTRUCTION"}
	in.Metadata.Tags = []Tag{{Key: "ASCII-KEY-INSTRUCTION", Value: "ASCII-VALUE-INSTRUCTION"}}
	in.Metadata.AppSettingKeys = []string{"ASCII-SETTING-KEY"}
	report := build(t, in, config())
	value, err := report.Value()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range value["evidence"].([]any) {
		delete(e.(map[string]any), "untrusted")
	}
	delete(value, "untrusted")
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ASCII-") {
		t.Fatal("ASCII trust exemption")
	}
	if !strings.Contains(encoded(t, report), "ASCII-NAME-INSTRUCTION") {
		t.Fatal("metadata disappeared")
	}
}

func TestUnicodeCategoryCorpus(t *testing.T) {
	for _, input := range []string{
		"a\x1b[31m\u200e\u200f\u202a\u2066\u2069b",
		"a\ud7ff\ue000\uf8ff\U000f0000\U0010ffffb",
		"a\u0378\u0380\ufffeb",
		"e\u0301" + strings.Repeat("界", 129),
		"\xff\xfe\xed\xa0\x80\xf4\x90\x80\x80\ufffd",
	} {
		got := sanitize(input)
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > 128 {
			t.Fatalf("invalid/cap: %q", got)
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cs, r) || unicode.Is(unicode.Co, r) {
				t.Fatalf("prohibited category %U", r)
			}
			if !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsNumber(r) && !unicode.IsPunct(r) && !unicode.IsSymbol(r) && !unicode.IsSpace(r) {
				t.Fatalf("unassigned category %U", r)
			}
		}
	}
}

func TestAllFormatLeakageCorpus(t *testing.T) {
	in := sample()
	in.Metadata.Name = "h\u200bttps://evil.test/name"
	in.Metadata.Callers = []string{"https://evil.test", "//evil.test", "www.evil.test"}
	in.Metadata.Tags = []Tag{{Key: "owner", Value: "PRIVATE-TAG-SECRET"}}
	e := &in.Assessment.Evidence[0]
	e.Summary = "PRIVATE-TAG-SECRET https://evil.test"
	e.Untrusted = map[string]string{"caller": "PRIVATE-TAG-SECRET", "appSettingValue:0": "PRIVATE-SETTING-SECRET"}
	e.Details = map[string]any{"appSettings": map[string]any{"KEY": "PRIVATE-SETTING-SECRET"}, "raw": "https://evil.test"}
	report, err := BuildForMCP(in, config())
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "jsonc", "yaml", "tsv", "table", "none"} {
		var out bytes.Buffer
		if err := Render(&out, format, []Outcome{Completed(report)}); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"PRIVATE-TAG-SECRET", "PRIVATE-SETTING-SECRET", "evil.test", "\x1b"} {
			if strings.Contains(out.String(), forbidden) {
				t.Fatalf("%s leaked %s", format, forbidden)
			}
		}
	}
}

func TestReducerCartesianCorpus(t *testing.T) {
	yes := Completed(build(t, sample(), config()))
	in := sample()
	in.Assessment.Evidence[0].Status = verdict.StatusAbsent
	tentative := Completed(build(t, in, config()))
	in.Assessment.Evidence = append(in.Assessment.Evidence, verdict.Evidence{ID: "disk.blocker", Tier: verdict.TierBlocker, Status: verdict.StatusPresent})
	no := Completed(build(t, in, config()))
	cases := []struct {
		o              Outcome
		priority, code int
	}{
		{Failed(Usage), 0, 2}, {Failed(Runtime), 1, 1}, {Outcome{}, 1, 1},
		{Completed(Report{}), 1, 1}, {Failed("cancelled"), 1, 1},
		{Failed(NothingEvaluable), 2, 4}, {Failed(NotFound), 3, 3},
		{no, 4, 10}, {tentative, 5, 11}, {yes, 6, 0},
	}
	for _, a := range cases {
		for _, b := range cases {
			for _, c := range cases {
				best := a
				if b.priority < best.priority {
					best = b
				}
				if c.priority < best.priority {
					best = c
				}
				outcomes := []Outcome{a.o, b.o, c.o}
				original := append([]Outcome{}, outcomes...)
				for _, flag := range []bool{false, true} {
					want := best.code
					if !flag && best.priority >= 4 {
						want = 0
					}
					if got := ExitCode(outcomes, flag); got != want {
						t.Fatalf("priorities %d/%d/%d flag=%v got=%d want=%d", a.priority, b.priority, c.priority, flag, got, want)
					}
				}
				if !reflect.DeepEqual(original, outcomes) {
					t.Fatal("reducer mutated outcomes")
				}
			}
		}
	}
}

func TestEvidenceCoverageAndInputImmutability(t *testing.T) {
	in := sample()
	in.Assessment.Evidence[0].Summary = "Provider text is not a trusted template."
	in.Assessment.Evidence = append(in.Assessment.Evidence, in.Assessment.Evidence[0])
	before, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	report := build(t, in, config())
	after, err := json.Marshal(in)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input mutated")
	}
	value, err := report.Value()
	if err != nil {
		t.Fatal(err)
	}
	if len(value["evidence"].([]any)) != len(in.Assessment.Evidence) {
		t.Fatal("passed signal lost")
	}
	if value["coverage"].(map[string]any)["total"] != json.Number("4") {
		t.Fatal("coverage drift")
	}
}
