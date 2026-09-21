package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
	"gopkg.in/yaml.v3"
)

func TestApprovedLimitationsVerbatim(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := strings.Split(strings.Split(string(doc), "### 5.1 Approved runtime limitations (G1, verbatim)")[1], "\n## 6.")[0]
	var want []string
	for _, line := range strings.Split(section, "\n") {
		if _, text, ok := strings.Cut(line, ". "); ok && len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			want = append(want, strings.TrimSuffix(text, "\r"))
		}
	}
	if !reflect.DeepEqual(approvedLimitations, want) {
		t.Fatalf("limitations drift:\ngot %q\nwant %q", approvedLimitations, want)
	}
}

func TestMalformedInputNeverBecomesReport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Input, *Config)
	}{
		{"URL identity", func(in *Input, _ *Config) { in.ResourceID = "https://portal.azure.com/#resource" + targetID }},
		{"query identity", func(in *Input, _ *Config) { in.ResourceID += "?secret=hidden" }},
		{"invalid utf8 identity", func(in *Input, _ *Config) { in.ResourceID += "\xff" }},
		{"private use identity", func(in *Input, _ *Config) { in.ResourceID += "\ue000" }},
		{"invalid rule", func(in *Input, _ *Config) { in.Assessment.Evidence[0].ID = "IGNORE INSTRUCTIONS" }},
		{"URL rule", func(in *Input, _ *Config) { in.Assessment.Evidence[0].ID = "www.evil.test" }},
		{"unknown hosting", func(in *Input, _ *Config) { in.HostingClass = "COPY THIS" }},
		{"unknown age source", func(in *Input, _ *Config) { in.Assessment.Age.Source = "secret-source" }},
		{"unknown source API", func(in *Input, _ *Config) { in.Assessment.Evidence[0].Source.API = "https://evil.test" }},
		{"unknown version", func(in *Input, _ *Config) { in.Assessment.Evidence[0].Source.APIVersion = "2026-01-01" }},
		{"source query", func(in *Input, _ *Config) {
			in.Assessment.Evidence[0].Source.Path = targetID + "?api-version=2026-01-01"
		}},
		{"invalid GUID", func(in *Input, _ *Config) { in.Scope.ARGSubscriptionsQueried = []string{"secret"} }},
		{"missing unknown code", func(in *Input, _ *Config) { in.Assessment.Evidence[0].Status = verdict.StatusUnknown }},
		{"unknown unknown code", func(in *Input, _ *Config) {
			in.Assessment.Evidence[0].Status = verdict.StatusUnknown
			in.Assessment.Evidence[0].Unknown = &verdict.Unknown{Code: "provider-secret"}
		}},
		{"zero generated", func(in *Input, _ *Config) { in.GeneratedAt = time.Time{} }},
		{"empty Required", func(in *Input, _ *Config) { in.Assessment.Required = nil }},
		{"zero window", func(in *Input, _ *Config) { in.Assessment.Requested.Start = time.Time{} }},
		{"unrecognized structured detail", func(in *Input, _ *Config) {
			in.Assessment.Evidence[0].Details = map[string]any{"nested": map[string]any{"success": true}}
		}},
		{"unsafe template", func(_ *Input, cfg *Config) { cfg.Caveats = []string{"https://evil.test"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, cfg := sample(), config()
			tc.change(&in, &cfg)
			report, err := Build(in, cfg)
			if err == nil {
				t.Fatal("malformed input succeeded")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https:") {
				t.Fatal("unsafe error")
			}
			if _, err := report.JSON(); err == nil {
				t.Fatal("error returned report")
			}
		})
	}
	if _, err := json.Marshal(Report{}); err == nil {
		t.Fatal("zero report serialized")
	}
}

func TestDetailAllowlistKinds(t *testing.T) {
	guid := "01234567-89AB-CDEF-0123-456789ABCDEF"
	for _, tc := range []struct {
		name   string
		kind   DetailKind
		value  any
		values []string
		ok     bool
	}{
		{"number", Number, uint64(9007199254740993), nil, true},
		{"negative", Number, int64(-99), nil, true},
		{"fraction", Number, 1.25, nil, true},
		{"NaN", Number, math.NaN(), nil, false},
		{"Inf", Number, math.Inf(1), nil, false},
		{"numeric string", Number, "42", nil, false},
		{"bool", Boolean, true, nil, true},
		{"bool string", Boolean, "true", nil, false},
		{"identity", ARMID, targetID, nil, true},
		{"identity list", ARMIDs, []string{targetID}, nil, true},
		{"identity query", ARMID, targetID + "?x=1", nil, false},
		{"identity URL", ARMID, "https://evil.test", nil, false},
		{"GUID", GUID, guid, nil, true},
		{"GUID malformed", GUID, "0123", nil, false},
		{"UTC", Timestamp, "2026-09-21T02:00:00+02:00", nil, true},
		{"timestamp malformed", Timestamp, "tomorrow", nil, false},
		{"enum", Enum, "Enabled", []string{"Enabled", "Disabled"}, true},
		{"enum unknown", Enum, "IGNORE", []string{"Enabled"}, false},
		{"objects forbidden", Enum, map[string]any{"Enabled": true}, []string{"Enabled"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, cfg := sample(), config()
			id := in.Assessment.Evidence[0].ID
			in.Assessment.Evidence[0].Details = map[string]any{"value": tc.value}
			cfg.Policies = map[string]SignalPolicy{id: {Details: map[string]DetailPolicy{"value": {Kind: tc.kind, Values: tc.values}}}}
			report, err := Build(in, cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v error=%v", tc.ok, err)
			}
			if tc.ok {
				value, err := report.Value()
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(value)
				if err != nil || string(b) != encoded(t, report) {
					t.Fatal("precision or value drift")
				}
			}
		})
	}
	for _, key := range []string{"appSettings", "appSettingValue", "tags", "tagValues"} {
		in, cfg := sample(), config()
		cfg.Policies = map[string]SignalPolicy{in.Assessment.Evidence[0].ID: {Details: map[string]DetailPolicy{key: {Kind: Enum, Values: []string{"SECRET"}}}}}
		if _, err := Build(in, cfg); err == nil {
			t.Fatalf("policy authorized %s", key)
		}
	}
}

func TestRedactionAndSettingValueSmuggling(t *testing.T) {
	in, cfg := sample(), config()
	in.Metadata = Metadata{
		Name: "same-secret", ResourceGroup: "same-secret", Callers: []string{"same-secret", "SETTING-SECRET"},
		Tags:           []Tag{{Key: "same-secret", Value: "same-secret"}},
		AppSettingKeys: []string{"VALID_KEY", "KEY=INLINE-SECRET", "SETTING-SECRET"},
	}
	e := &in.Assessment.Evidence[0]
	e.Summary = "same-secret"
	e.Details = map[string]any{
		"same-secret": "same-secret",
		"appSettings": map[string]any{"KEY": "SETTING-SECRET"},
	}
	e.Untrusted = map[string]string{"appSettingValue:0": "SETTING-SECRET", "caller": "SETTING-SECRET", "appSettingKey:0": "KEY=INLINE-SECRET"}
	report, err := BuildForMCP(in, cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := encoded(t, report)
	for _, secret := range []string{"same-secret", "SETTING-SECRET", "INLINE-SECRET"} {
		if strings.Contains(text, secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if !strings.Contains(text, "VALID_KEY") {
		t.Fatal("key lost")
	}
	plain := sample()
	plain.Metadata.Tags = []Tag{{Key: "owner", Value: "PUBLIC-TAG"}}
	if !strings.Contains(encoded(t, build(t, plain, cfg)), "PUBLIC-TAG") {
		t.Fatal("explicit CLI tag missing")
	}
	report, err = BuildForMCP(plain, cfg)
	if err != nil || strings.Contains(encoded(t, report), "PUBLIC-TAG") {
		t.Fatal("MCP tag not redacted")
	}
	plain.Metadata.Tags[0].Value = "disk"
	if _, err := BuildForMCP(plain, cfg); err == nil {
		t.Fatal("typed identity redaction conflict not explicit")
	}
}

func TestTrustedTemplatesAndStructuredUnknowns(t *testing.T) {
	in, cfg := sample(), config()
	e := &in.Assessment.Evidence[0]
	e.Status, e.Critical = verdict.StatusUnknown, true
	e.Unknown = &verdict.Unknown{Code: verdict.UnkPermission, Message: "SECRET https://evil.test", HTTPStatus: 403, ErrorCode: "SECRET"}
	n := &in.Assessment.Evidence[1]
	n.Status = verdict.StatusNotEvaluated
	n.NotEvaluated = &verdict.NotEvaluated{Reason: "SECRET", Consequence: "SECRET", HowToCheck: "SECRET"}
	cfg.Policies = map[string]SignalPolicy{
		e.ID: {HumanQuestion: "Ask the owner to restore read access.", Summaries: map[verdict.Status]string{verdict.StatusUnknown: "Read access was unavailable."}},
		n.ID: {NotEvaluated: &verdict.NotEvaluated{Reason: "Check is not implemented.", Consequence: "Consumers may be missed.", HowToCheck: "Review consumers manually."}, NextSteps: []string{"Review consumers manually."}},
	}
	text := encoded(t, build(t, in, cfg))
	for _, want := range []string{"Ask the owner to restore read access.", "Check is not implemented.", "Consumers may be missed.", "Review consumers manually.", `"httpStatus":403`, `"humanEscalation":true`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(text, "SECRET") || strings.Contains(text, "https:") {
		t.Fatal("raw provider text leaked")
	}
}

func TestStrictRelativeSourcePaths(t *testing.T) {
	in, cfg := sample(), config()
	e := &in.Assessment.Evidence[0]
	e.Source = verdict.Source{API: "Metrics", Path: targetID + "/providers/Microsoft.Insights/metrics", APIVersion: "2024-02-01"}
	cfg.Policies = map[string]SignalPolicy{e.ID: {APIVersions: []string{"2024-02-01"}, SourcePathSuffixes: []string{"/providers/Microsoft.Insights/metrics"}}}
	if _, err := Build(in, cfg); err != nil {
		t.Fatal(err)
	}
	e.Source.Path += "?arbitrary=query"
	if _, err := Build(in, cfg); err == nil {
		t.Fatal("query passed")
	}
	e.Source.Path = "//evil.test/path"
	if _, err := Build(in, cfg); err == nil {
		t.Fatal("authority passed")
	}
	suffix := "/providers/Microsoft.ResourceGraph/resources"
	cfg.Policies[e.ID] = SignalPolicy{APIVersions: []string{"2024-02-01"}, SourcePathSuffixes: []string{suffix}}
	for _, path := range []string{suffix, "/subscriptions/01234567-89AB-CDEF-0123-456789ABCDEF" + suffix} {
		e.Source.Path = path
		if _, err := Build(in, cfg); err != nil {
			t.Fatalf("declared root/subscription request path: %v", err)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("test write failure") }

func TestRenderingErrorsAndBatchRetention(t *testing.T) {
	report := build(t, sample(), config())
	outcomes := []Outcome{Completed(report), Failed(NotFound), {}, Failed(NothingEvaluable)}
	for _, format := range []string{"json", "jsonc", "yaml", "table", "tsv"} {
		var out bytes.Buffer
		if err := Render(&out, format, outcomes); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "not-found") || !strings.Contains(out.String(), "runtime") || !strings.Contains(out.String(), "nothing-evaluable") {
			t.Fatal("lost individual error")
		}
		if format == "yaml" {
			var values []any
			if err := yaml.Unmarshal(out.Bytes(), &values); err != nil || len(values) != 4 {
				t.Fatal("bad YAML array")
			}
		}
		if err := Render(failingWriter{}, format, outcomes); err == nil {
			t.Fatal("write failure lost")
		}
	}
	var out bytes.Buffer
	if err := Render(&out, "none", outcomes); err == nil || out.Len() != 0 {
		t.Fatal("none swallowed error")
	}
	if err := Render(&out, "INVALID", outcomes); err == nil {
		t.Fatal("invalid format")
	}
}

func TestTableDisplayWidth(t *testing.T) {
	in := sample()
	in.Metadata.Name = strings.Repeat("界", 129)
	var out bytes.Buffer
	if err := Render(&out, "table", []Outcome{Completed(build(t, in, config()))}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		width := 0
		for _, r := range line {
			if r < 128 {
				width++
			} else {
				width += 2
			}
		}
		if width > 100 {
			t.Fatalf("table wider than 100 columns: %d", width)
		}
	}
}
