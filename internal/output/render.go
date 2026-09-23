package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// FailureKind is a closed outcome class, never a provider message or verdict.
type FailureKind string

// Failure kinds use G3 precedence, not numeric maximum.
const (
	Usage            FailureKind = "usage"
	Runtime          FailureKind = "runtime"
	NothingEvaluable FailureKind = "nothing-evaluable"
	NotFound         FailureKind = "not-found"
)

// Outcome retains an individual completed report or explicit failure. Private
// state prevents a raw Result, cancellation, or failed build becoming a verdict.
type Outcome struct {
	report  Report
	failure FailureKind
}

// Completed wraps a sealed report. An invalid/zero report is a runtime outcome.
func Completed(report Report) Outcome {
	if len(report.data) == 0 {
		return Failed(Runtime)
	}
	return Outcome{report: report}
}

// Failed produces a tool-authored error. Unknown failure kinds become runtime
// errors, never completed assessments. Provider errors are intentionally absent.
func Failed(kind FailureKind) Outcome {
	if !slices.Contains([]FailureKind{Usage, Runtime, NothingEvaluable, NotFound}, kind) {
		kind = Runtime
	}
	return Outcome{failure: kind}
}

func (o Outcome) kind() FailureKind {
	if len(o.report.data) == 0 && o.failure == "" {
		return Runtime
	}
	return o.failure
}

// ExitCode implements the complete G3 semantic reducer without changing inputs.
func ExitCode(outcomes []Outcome, exitOnVerdict bool) int {
	if len(outcomes) == 0 {
		return 4
	}
	for _, item := range []struct {
		kind FailureKind
		code int
	}{{Usage, 2}, {Runtime, 1}, {NothingEvaluable, 4}, {NotFound, 3}} {
		for _, o := range outcomes {
			if o.kind() == item.kind {
				return item.code
			}
		}
	}
	if !exitOnVerdict {
		return 0
	}
	for _, verdict := range []struct {
		value string
		code  int
	}{{"no", 10}, {"tentative", 11}} {
		for _, o := range outcomes {
			if o.report.verdict == verdict.value {
				return verdict.code
			}
		}
	}
	return 0
}

// IsHuman reports whether a format is meant to be read on a screen rather than
// parsed. A note addressed to a person belongs only in those; anywhere else it
// would be corruption in the middle of somebody's data.
func IsHuman(format string) bool { return format == "table" }

// ValidateFormat rejects unknown formats without echoing potentially unsafe text.
func ValidateFormat(format string) error {
	if !slices.Contains([]string{"json", "jsonc", "table", "tsv", "yaml", "none"}, format) {
		return errors.New("output must be json, jsonc, table, tsv, yaml or none")
	}
	return nil
}

func (o Outcome) bytes() ([]byte, error) {
	if o.kind() == "" {
		return o.report.JSON()
	}
	messages := map[FailureKind]string{
		Usage: "Invalid usage prevented assessment.", Runtime: "Assessment did not complete.",
		NothingEvaluable: "No signals were evaluable.", NotFound: "The resource was not found.",
	}
	codes := map[FailureKind]int{Usage: 2, Runtime: 1, NothingEvaluable: 4, NotFound: 3}
	return json.Marshal(map[string]any{"schemaVersion": "2", "error": map[string]any{
		"code": o.kind(), "message": messages[o.kind()], "exitCode": codes[o.kind()],
	}})
}

// View is how much of the report a human is shown. It travels with the call
// rather than sitting in a package variable: two renders can run at once, and
// one of them asking for everything must not change what the other prints.
type View struct {
	// Full prints every signal and the limitations verbatim, rather than the
	// verdict and what was found.
	Full bool
}

// Detailed asks for the complete view.
func Detailed() ViewOption { return func(v *View) { v.Full = true } }

// ViewOption configures one rendering.
type ViewOption func(*View)

// Render uses the same sealed JSON for all formats. jsonc intentionally uses
// plain JSON (valid JSONC), including off-TTY. none suppresses result output;
// failures remain explicit return errors for the caller's error stream.
func Render(w io.Writer, format string, outcomes []Outcome, options ...ViewOption) error {
	var view View
	for _, option := range options {
		option(&view)
	}
	if err := ValidateFormat(format); err != nil {
		return err
	}
	if format == "none" {
		if code := ExitCode(outcomes, false); code != 0 {
			return fmt.Errorf("assessment failed (exit %d)", code)
		}
		return nil
	}
	items := make([]json.RawMessage, 0, len(outcomes))
	for _, outcome := range outcomes {
		b, err := outcome.bytes()
		if err != nil {
			return err
		}
		items = append(items, b)
	}
	var value any = items
	if len(items) == 1 {
		value = items[0]
	}
	data, err := json.Marshal(value)
	if err != nil {
		return boundaryError()
	}
	switch format {
	case "json", "jsonc":
		data = append(data, '\n')
	case "yaml":
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return boundaryError()
		}
		data, err = yaml.Marshal(&node)
		if err != nil {
			return boundaryError()
		}
	case "table":
		data, err = tableOutput(items, view)
		if err != nil {
			return err
		}
	case "tsv":
		data, err = textOutput(items, format)
		if err != nil {
			return err
		}
	}
	_, err = w.Write(data)
	return err
}

// textOutput is the flat machine view behind tsv: one path-and-value row per
// field, so every field of the report is addressable by a script.
func textOutput(items []json.RawMessage, format string) ([]byte, error) {
	var out bytes.Buffer
	for i, item := range items {
		decoder := json.NewDecoder(bytes.NewReader(item))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, boundaryError()
		}
		if format == "table" {
			fmt.Fprintf(&out, "Target %d — evidence, not permission\n", i+1)
		}
		var lines []string
		flatten(value, "", &lines)
		for _, line := range lines {
			if format == "table" {
				line = strings.ReplaceAll(line, "\t", "  ")
				writeWrapped(&out, line)
			} else {
				fmt.Fprintf(&out, "%d\t%s", i+1, line)
			}
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}

func writeWrapped(out *bytes.Buffer, line string) {
	width := 0
	for _, r := range line {
		columns := 1
		if r >= 128 {
			// Conservatively account for East Asian/emoji terminal cell widths.
			columns = 2
		}
		if width+columns > 100 {
			out.WriteByte('\n')
			width = 0
		}
		out.WriteRune(r)
		width += columns
	}
}

// Flatten all fields rather than a verdict-only table: required limitations,
// unknowns and evidence remain visible in every non-none representation.
func flatten(value any, path string, lines *[]string) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			key := k
			if path != "" {
				key = path + "." + k
			}
			flatten(v[k], key, lines)
		}
	case []any:
		if len(v) == 0 {
			*lines = append(*lines, path+"\t[]")
		}
		for i, item := range v {
			flatten(item, fmt.Sprintf("%s[%d]", path, i), lines)
		}
	case string:
		// Freeform values are already single-line. JSON-escape separators such as
		// U+2028/2029 to keep row-oriented formats unambiguous.
		v = strings.ReplaceAll(strings.ReplaceAll(v, "\u2028", `\u2028`), "\u2029", `\u2029`)
		*lines = append(*lines, path+"\t"+v)
	default:
		*lines = append(*lines, fmt.Sprintf("%s\t%v", path, v))
	}
}
