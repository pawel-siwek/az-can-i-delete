package output

import (
	"errors"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
	"golang.org/x/text/unicode/norm"
)

// DetailKind grants one specific representation at a declared signal detail key.
type DetailKind string

// No kind permits arbitrary strings, objects, URLs, tags or app-setting values.
const (
	Number    DetailKind = "number"
	Boolean   DetailKind = "boolean"
	ARMID     DetailKind = "arm-id"
	ARMIDs    DetailKind = "arm-ids"
	GUID      DetailKind = "guid"
	Timestamp DetailKind = "timestamp"
	Enum      DetailKind = "enum"
)

// DetailPolicy is a per-key allowlist; Values is used only with Enum.
type DetailPolicy struct {
	Kind   DetailKind
	Values []string
}

// SignalPolicy supplies curated fixed templates and exact detail permissions.
// Nothing here may be constructed from collector/provider text. Empty templates
// use closed defaults. Source suffixes are fixed relative ARM operation suffixes.
type SignalPolicy struct {
	Details            map[string]DetailPolicy
	Summaries          map[verdict.Status]string
	Family             string
	Confidence         string
	APIVersions        []string
	SourcePathSuffixes []string
	NotEvaluated       *verdict.NotEvaluated
	HumanQuestion      string
	NextSteps          []string
	Caveats            []string
}

// Config holds trusted release/rules metadata and policy, not observation data.
// RedactTags suppresses known tag values throughout untrusted output; BuildForMCP
// forces it on. Unknown legacy metadata and sensitive containers are omitted with
// quarantine notices (including their keys). Other undeclared structures fail.
type Config struct {
	ToolVersion string
	RulesDate   string
	RedactTags  bool
	Policies    map[string]SignalPolicy
	Caveats     []string
}

var (
	ruleID            = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`)
	fieldKey          = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`)
	guidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	versionPattern    = regexp.MustCompile(`^(dev|v?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)$`)
	apiVersionPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:-preview)?$`)
	urlPattern        = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*:|//|www\.)`)
)

func boundaryError() error {
	return errors.New("invalid report input or output policy; no assessment emitted")
}

func validRuleID(s string) bool {
	return len(s) <= 128 && ruleID.MatchString(s) && !urlPattern.MatchString(s)
}

// Sanitized is the character half of ADR-0007's boundary: control, format,
// surrogate, private-use and unassigned runes removed, and what is left
// normalized to NFC. It is exported so that the one other place that has to
// apply this contract — the fixture recorder — runs this code rather than a
// second copy of the rules, because two copies agree until they do not and
// the one that drifts is the one nobody is reading.
//
// The length cap ADR-0007 also sets is applied by the callers that publish a
// report, not here: see ADR-0016 for the one boundary that must not truncate.
func Sanitized(s string) string { return cleanRunes(s) }

func cleanRunes(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cs, r) || unicode.Is(unicode.Co, r) {
			continue
		}
		// Go has no Cn table: only assigned, explicitly permitted categories pass.
		if unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return norm.NFC.String(b.String())
}

// Untrusted applies the whole ADR-0007 contract, the cap included, to a value
// that is published outside a report. Cordon status is that case: it prints a
// caller and, for a damaged tag, the raw value, and neither may reach a reader
// by a path that skips the rules a report follows.
func Untrusted(s string) string { return sanitize(s) }

func sanitize(s string) string {
	s = cleanRunes(s)
	if urlPattern.MatchString(s) {
		return "(URL omitted)"
	}
	runes := []rune(s)
	if len(runes) > 128 {
		return string(runes[:127]) + "…"
	}
	return s
}

func fixedText(s string) bool {
	return utf8.ValidString(s) && cleanRunes(s) == s && !urlPattern.MatchString(s)
}

func canonicalID(s string) (armid.Target, error) {
	if !strings.HasPrefix(s, "/subscriptions/") && !strings.HasPrefix(strings.ToLower(s), "/subscriptions/") {
		return armid.Target{}, boundaryError()
	}
	if strings.ContainsAny(s, "?#\\") || urlPattern.MatchString(s) || !utf8.ValidString(s) || cleanRunes(s) != s {
		return armid.Target{}, boundaryError()
	}
	target, err := armid.Parse(s)
	if err != nil {
		return armid.Target{}, boundaryError()
	}
	return target, nil
}

func utc(t time.Time) (string, error) {
	t = t.UTC()
	if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return "", boundaryError()
	}
	return t.UTC().Format(time.RFC3339Nano), nil
}

func typedDetail(value any, p DetailPolicy) (any, error) {
	switch p.Kind {
	case Boolean:
		if v, ok := value.(bool); ok {
			return v, nil
		}
	case Number:
		if value != nil {
			v := reflect.ValueOf(value)
			switch v.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return v.Int(), nil
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				return v.Uint(), nil
			case reflect.Float32, reflect.Float64:
				if !math.IsNaN(v.Float()) && !math.IsInf(v.Float(), 0) {
					return v.Float(), nil
				}
			}
		}
	case ARMIDs:
		if ids, ok := value.([]string); ok {
			out := make([]string, 0, len(ids))
			for _, id := range ids {
				target, err := canonicalID(id)
				if err != nil {
					return nil, err
				}
				out = append(out, target.ID)
			}
			return out, nil
		}
	default:
		s, ok := value.(string)
		if !ok {
			return nil, boundaryError()
		}
		switch p.Kind {
		case ARMID:
			t, err := canonicalID(s)
			if err != nil {
				return nil, err
			}
			return t.ID, nil
		case GUID:
			if guidPattern.MatchString(s) {
				return strings.ToLower(s), nil
			}
		case Timestamp:
			t, err := time.Parse(time.RFC3339Nano, s)
			if err == nil {
				return utc(t)
			}
		case Enum:
			if slices.Contains(p.Values, s) && fixedText(s) {
				return s, nil
			}
		}
	}
	return nil, boundaryError()
}

func validatePolicy(p SignalPolicy) error {
	if !slices.Contains(families, p.Family) || !slices.Contains(confidences, p.Confidence) {
		return boundaryError()
	}
	for key, detail := range p.Details {
		lower := strings.ToLower(key)
		if !fieldKey.MatchString(key) || strings.Contains(lower, "setting") || strings.Contains(lower, "tag") {
			return boundaryError()
		}
		switch detail.Kind {
		case Number, Boolean, ARMID, ARMIDs, GUID, Timestamp:
		case Enum:
			if len(detail.Values) == 0 {
				return boundaryError()
			}
		default:
			return boundaryError()
		}
		for _, s := range detail.Values {
			if !fixedText(s) {
				return boundaryError()
			}
		}
	}
	texts := append([]string{p.Family, p.Confidence, p.HumanQuestion}, p.NextSteps...)
	texts = append(texts, p.Caveats...)
	for _, s := range p.Summaries {
		texts = append(texts, s)
	}
	if p.NotEvaluated != nil {
		texts = append(texts, p.NotEvaluated.Reason, p.NotEvaluated.Consequence, p.NotEvaluated.HowToCheck)
		if p.NotEvaluated.Reason == "" || p.NotEvaluated.Consequence == "" || p.NotEvaluated.HowToCheck == "" {
			return boundaryError()
		}
	}
	for _, s := range texts {
		if !fixedText(s) {
			return boundaryError()
		}
	}
	for _, s := range p.APIVersions {
		if !apiVersionPattern.MatchString(s) {
			return boundaryError()
		}
	}
	for _, s := range p.SourcePathSuffixes {
		if !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "?#\\") || strings.Contains(s, "..") || !fixedText(s) {
			return boundaryError()
		}
	}
	return nil
}

var families = []string{"", "unknown", "structural", "reverse-ref", "data-plane", "metrics", "activity-log", "tags", "kb", "age", "derived"}
var confidences = []string{"", "unknown", "verified", "heuristic", "inferred", "sampled"}
