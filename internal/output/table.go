package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The table view is for a person at a terminal. It prints every signal the
// assessment collected, one row each with its summary, plus the verdict, the
// coverage and the limitations: a readable layout, not a smaller one. Nothing
// is dropped here that the JSON carries — the machine formats stay flat.
const tableWidth = 100

func tableOutput(items []json.RawMessage) ([]byte, error) {
	var out bytes.Buffer
	for i, item := range items {
		decoder := json.NewDecoder(bytes.NewReader(item))
		decoder.UseNumber()
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			return nil, boundaryError()
		}
		if i > 0 {
			out.WriteByte('\n')
		}
		fmt.Fprintf(&out, "Target %d — evidence, not permission\n", i+1)
		if failure, ok := value["error"].(map[string]any); ok {
			writeField(&out, "error", text(failure["code"])+" — "+text(failure["message"]))
			writeField(&out, "exit", text(failure["exitCode"]))
			continue
		}
		writeHeader(&out, value)
		writeEvidence(&out, value)
		writeList(&out, "Limitations", textList(value["limitations"]))
	}
	return out.Bytes(), nil
}

func writeHeader(out *bytes.Buffer, value map[string]any) {
	writeField(out, "resource", text(value["resourceId"]))
	verdict := text(value["verdict"])
	if class := text(value["reasonClass"]); class != "" {
		verdict += " (" + class + ")"
	}
	writeField(out, "verdict", verdict)
	if age, ok := value["age"].(map[string]any); ok {
		writeField(out, "age", fmt.Sprintf("at least %s d (%s, %s)",
			text(age["lowerBoundDays"]), text(age["confidence"]), text(age["source"])))
	}
	if window, ok := value["window"].(map[string]any); ok {
		requested, _ := window["requested"].(map[string]any)
		effective, _ := window["effective"].(map[string]any)
		writeField(out, "window", fmt.Sprintf("requested %s d, effective %s d",
			text(requested["days"]), text(effective["days"])))
	}
	if coverage, ok := value["coverage"].(map[string]any); ok {
		writeField(out, "coverage", fmt.Sprintf("%s signals: %s evaluated, %s unknown (%s critical), %s not evaluated",
			text(coverage["total"]), text(coverage["evaluated"]), text(coverage["unknown"]),
			text(coverage["criticalUnknown"]), text(coverage["notEvaluated"])))
	}
	if scope, ok := value["scope"].(map[string]any); ok {
		writeField(out, "scope", fmt.Sprintf("Resource Graph visible: %s; Activity Log: %s d",
			text(scope["argVisible"]), text(scope["activityLogDays"])))
	}
	writeField(out, "rules", fmt.Sprintf("%s (tool %s)", text(value["rulesDate"]), text(value["toolVersion"])))
	if replay, _ := value["replay"].(bool); replay {
		writeField(out, "source", "recorded — this is replayed evidence, not a live assessment")
	}
	for _, reason := range textList(value["reasons"]) {
		writeField(out, "because", reason)
	}
	if escalate, _ := value["humanEscalation"].(bool); escalate {
		writeField(out, "ask a human", text(value["requiredHumanQuestion"]))
	}
}

// writeEvidence prints every collected signal. A signal is one row plus its
// summary, so nothing the report carries is hidden from the terminal.
func writeEvidence(out *bytes.Buffer, value map[string]any) {
	evidence, ok := value["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		return
	}
	out.WriteString("\nEvidence\n")
	for _, item := range evidence {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		status := text(row["status"])
		if unknown, ok := row["unknown"].(map[string]any); ok {
			status += "(" + text(unknown["code"]) + ")"
		}
		// A critical unknown is what keeps a `yes` out of reach, so it is marked.
		if critical, _ := row["critical"].(bool); critical && text(row["status"]) == "unknown" {
			status += " !"
		}
		fmt.Fprintf(out, "  %-16s %-22s %s\n", text(row["tierName"]), status, text(row["id"]))
		writeIndented(out, text(row["summary"]))
		if notEvaluated, ok := row["notEvaluated"].(map[string]any); ok {
			writeIndented(out, "not evaluated: "+text(notEvaluated["reason"]))
			writeIndented(out, "consequence: "+text(notEvaluated["consequence"]))
			writeIndented(out, "how to check: "+text(notEvaluated["howToCheck"]))
		}
		if actionable(row) {
			for _, step := range textList(row["nextSteps"]) {
				writeIndented(out, "next: "+step)
			}
		}
	}
}

// actionable reports whether a signal leaves the reader something to do: a
// dependency or activity that was found, or a gap that could not be read.
// Silence that was successfully established needs no next step.
func actionable(row map[string]any) bool {
	switch text(row["status"]) {
	case "unknown":
		return true
	case "present":
		switch text(row["tierName"]) {
		case "BLOCKER", "HARD_DEPENDENCY", "LIVE_ACTIVITY", "DESIGN_INTENT":
			return true
		}
	}
	return false
}

func writeList(out *bytes.Buffer, title string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s\n", title)
	for _, value := range values {
		writeWrappedAt(out, "  - ", "    ", value)
	}
}

func writeField(out *bytes.Buffer, name, value string) {
	if value == "" {
		return
	}
	writeWrappedAt(out, fmt.Sprintf("  %-13s ", name), "                ", value)
}

func writeIndented(out *bytes.Buffer, value string) {
	if value == "" {
		return
	}
	writeWrappedAt(out, "      ", "      ", value)
}

// writeWrappedAt wraps on word boundaries inside the terminal width, counting
// wide runes as two columns so an East Asian name cannot push a line over. A
// single word too long to fit, such as a resource id, is split rather than
// truncated: the table shows everything the report carries.
func writeWrappedAt(out *bytes.Buffer, prefix, continuation, value string) {
	words := strings.Fields(value)
	if len(words) == 0 {
		return
	}
	line, width := prefix, displayWidth(prefix)
	for i, word := range words {
		if i > 0 {
			if width+1+displayWidth(word) > tableWidth {
				out.WriteString(line + "\n")
				line, width = continuation, displayWidth(continuation)
			} else {
				line, width = line+" ", width+1
			}
		}
		for _, chunk := range split(word, tableWidth-displayWidth(continuation)) {
			if width+displayWidth(chunk) > tableWidth {
				out.WriteString(line + "\n")
				line, width = continuation, displayWidth(continuation)
			}
			line, width = line+chunk, width+displayWidth(chunk)
		}
	}
	out.WriteString(line + "\n")
}

// split breaks a word that cannot fit on one line into display-width chunks.
func split(word string, width int) []string {
	if width < 1 {
		width = 1
	}
	if displayWidth(word) <= width {
		return []string{word}
	}
	var chunks []string
	var current strings.Builder
	used := 0
	for _, r := range word {
		size := 1
		if r >= 128 {
			size = 2
		}
		if used+size > width {
			chunks = append(chunks, current.String())
			current.Reset()
			used = 0
		}
		current.WriteRune(r)
		used += size
	}
	if current.Len() > 0 {
		chunks = append(chunks, current.String())
	}
	return chunks
}

func displayWidth(value string) int {
	width := 0
	for _, r := range value {
		if r >= 128 {
			width += 2
			continue
		}
		width++
	}
	return width
}

// text renders a JSON scalar for display. Anything else is left out rather
// than printed as a Go value.
func text(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		// Line and paragraph separators would break a row-oriented view.
		return strings.ReplaceAll(strings.ReplaceAll(typed, "\u2028", `\u2028`), "\u2029", `\u2029`)
	case bool:
		return fmt.Sprintf("%t", typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

// textList renders a JSON array of scalars.
func textList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if rendered := text(item); rendered != "" {
			out = append(out, rendered)
		}
	}
	return out
}
