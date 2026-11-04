package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The table view answers the question that was asked — can I delete this? —
// and then gets out of the way.
//
// A run collects fifty-odd signals and most of them find nothing, which is the
// point: silence is what a `yes` is made of. Printing all of it buries the
// verdict, so the default view shows what was found, what could not be read,
// and nothing else. The rest is one flag away and always in the JSON.
const tableWidth = 100

// verdictBanner is the headline and the one sentence that says what it means.
// Nothing here is collected from Azure; it is the tool's own text.
var verdictBanner = map[string]struct{ icon, word, remark string }{
	"yes": {"✅", "YES",
		"No evidence of use was found. That is not proof it is unused — nothing here can see a consumer that only names this resource in code, a pipeline or a config file."},
	"no": {"⛔", "NO",
		"This resource is IN USE. See the evidence below."},
	"tentative": {"⚠️", "TENTATIVE",
		"I could not verify everything, so I do not know whether you can delete this. Read the evidence below and decide."},
}

func tableOutput(items []json.RawMessage, view View) ([]byte, error) {
	var out bytes.Buffer
	p := painter(view.Color)
	for i, item := range items {
		decoder := json.NewDecoder(bytes.NewReader(item))
		decoder.UseNumber()
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			return nil, boundaryError()
		}
		if i > 0 {
			out.WriteString("\n")
		}
		if failure, ok := value["error"].(map[string]any); ok {
			fmt.Fprintf(&out, "%s\n\n", p.paint(onRed, " 💥 ERROR — "+text(failure["code"])+" "))
			writeIndented(&out, text(failure["message"]))
			continue
		}
		writeVerdict(&out, p, value)
		writeFindings(&out, p, value)
		writeFooter(&out, p, value, view)
		if view.Full {
			writeEverySignal(&out, p, value)
			writeList(&out, "Limitations", textList(value["limitations"]))
		}
	}
	return out.Bytes(), nil
}

// writeVerdict is the answer, first, in three lines.
func writeVerdict(out *bytes.Buffer, p painter, value map[string]any) {
	banner, known := verdictBanner[text(value["verdict"])]
	if !known {
		banner = struct{ icon, word, remark string }{"❔", strings.ToUpper(text(value["verdict"])), ""}
	}
	name := resourceName(text(value["resourceId"]))
	fmt.Fprintf(out, "%s %s %s\n\n", p.badge(text(value["verdict"]), banner.icon, banner.word), p.paint(dim, "—"), p.paint(bold, name))
	if banner.remark != "" {
		writeWrappedStyled(out, "    ", "    ", banner.remark, p.style(bold))
	}
	if replay, _ := value["replay"].(bool); replay {
		fmt.Fprintf(out, "\n%s\n", p.paint(magenta, "🎞️  RECORDED — replayed evidence, not a live assessment."))
	}
	if question := text(value["requiredHumanQuestion"]); question != "" {
		if escalate, _ := value["humanEscalation"].(bool); escalate {
			out.WriteString("\n")
			writeWrappedStyled(out, "    ❓ ", "       ", question, p.style(bold+yellow))
		}
	}
}

// resourceName is the last segment of the ARM id, which is what a person calls
// the thing. The whole id is in the footer and in the JSON.
func resourceName(id string) string {
	if index := strings.LastIndex(id, "/"); index >= 0 && index+1 < len(id) {
		return id[index+1:]
	}
	return id
}

// writeFindings prints what was actually found and what could not be read.
// Everything that looked and found nothing is counted, not listed.
func writeFindings(out *bytes.Buffer, p painter, value map[string]any) {
	evidence, _ := value["evidence"].([]any)
	var found, unreadable []map[string]any
	var skipped []string
	quiet := 0
	for _, item := range evidence {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch text(row["status"]) {
		case "present":
			if decisive(row) {
				found = append(found, row)
			} else {
				quiet++
			}
		case "unknown":
			unreadable = append(unreadable, row)
		case "not_evaluated":
			skipped = append(skipped, text(row["id"]))
		default:
			quiet++
		}
	}

	if len(found) > 0 {
		fmt.Fprintf(out, "\n%s\n", p.paint(bold+red, "🔴  Found"))
		for _, row := range found {
			writeSignal(out, p, row)
		}
	}
	if len(unreadable) > 0 {
		fmt.Fprintf(out, "\n%s\n", p.paint(bold+yellow, fmt.Sprintf("🚧  Could not check (%d)", len(unreadable))))
		for _, row := range unreadable {
			writeSignal(out, p, row)
		}
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		fmt.Fprintf(out, "\n%s\n", p.paint(bold+blue, fmt.Sprintf("🔍  Not evaluated (%d)", len(skipped))))
		writeWrappedStyled(out, "    ", "    ", strings.Join(skipped, ", "), p.style(dim))
	}
	if quiet > 0 {
		fmt.Fprintf(out, "\n%s\n", p.paint(green, fmt.Sprintf("✅  %d signals looked and found nothing", quiet)))
	}
}

// decisive reports whether a present signal is worth a reader's attention.
// Existence and Resource Graph visibility are present on every successful run.
func decisive(row map[string]any) bool {
	switch text(row["tierName"]) {
	case "BLOCKER", "HARD_DEPENDENCY", "LIVE_ACTIVITY", "DESIGN_INTENT":
		return true
	}
	return false
}

func writeSignal(out *bytes.Buffer, p painter, row map[string]any) {
	mark := ""
	if critical, _ := row["critical"].(bool); critical && text(row["status"]) == "unknown" {
		mark = " " + p.paint(bold+red, "‼")
	}
	if unknown, ok := row["unknown"].(map[string]any); ok {
		fmt.Fprintf(out, "    %s %s%s\n", p.paint(magenta, text(row["id"])), p.paint(yellow, "("+text(unknown["code"])+")"), mark)
	} else {
		fmt.Fprintf(out, "    %s%s\n", p.paint(magenta, text(row["id"])), mark)
	}
	writeWrappedAt(out, "      ", "      ", text(row["summary"]))
	// The code is a category; the reason is the one thing that tells a reader
	// whether this is theirs to fix. `transient` alone sends them nowhere.
	if unknown, ok := row["unknown"].(map[string]any); ok {
		if reason := text(unknown["reason"]); reason != "" {
			writeWrappedStyled(out, "      ↳ ", "        ", reason, p.style(dim))
		}
	}
	for _, step := range textList(row["nextSteps"]) {
		writeWrappedStyled(out, "      → ", "        ", step, p.style(cyan))
	}
}

// writeFooter is one line of provenance and one of what else is available.
func writeFooter(out *bytes.Buffer, p painter, value map[string]any, view View) {
	parts := []string{}
	if coverage, ok := value["coverage"].(map[string]any); ok {
		parts = append(parts, fmt.Sprintf("%s/%s checked", text(coverage["evaluated"]), text(coverage["total"])))
	}
	if window, ok := value["window"].(map[string]any); ok {
		if effective, ok := window["effective"].(map[string]any); ok {
			parts = append(parts, "window "+text(effective["days"])+" d")
		}
	}
	if age, ok := value["age"].(map[string]any); ok {
		parts = append(parts, "age ≥"+text(age["lowerBoundDays"])+" d")
	}
	parts = append(parts, "rules "+text(value["rulesDate"]), "v"+text(value["toolVersion"]))
	fmt.Fprintf(out, "\n    %s\n", p.paint(dim, strings.Join(parts, " · ")))
	if !view.Full {
		fmt.Fprintf(out, "    %s\n", p.paint(dim, "everything: --full · machine-readable: -o json"))
	}
	writeWrappedStyled(out, "    ", "    ", text(value["resourceId"]), p.style(dim))
}

// writeEverySignal is the complete list, for --full.
func writeEverySignal(out *bytes.Buffer, p painter, value map[string]any) {
	evidence, ok := value["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s\n", p.paint(bold, "Evidence"))
	for _, item := range evidence {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		status := text(row["status"])
		if unknown, ok := row["unknown"].(map[string]any); ok {
			status += "(" + text(unknown["code"]) + ")"
		}
		if critical, _ := row["critical"].(bool); critical && text(row["status"]) == "unknown" {
			status += " !"
		}
		fmt.Fprintf(out, "  %-16s %-22s %s\n", text(row["tierName"]), status, text(row["id"]))
		writeIndented(out, text(row["summary"]))
		if unknown, ok := row["unknown"].(map[string]any); ok {
			if reason := text(unknown["reason"]); reason != "" {
				writeIndented(out, "why: "+reason)
			}
		}
		if notEvaluated, ok := row["notEvaluated"].(map[string]any); ok {
			writeIndented(out, "not evaluated: "+text(notEvaluated["reason"]))
			writeIndented(out, "consequence: "+text(notEvaluated["consequence"]))
			writeIndented(out, "how to check: "+text(notEvaluated["howToCheck"]))
		}
		for _, step := range textList(row["nextSteps"]) {
			writeIndented(out, "next: "+step)
		}
	}
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
	writeWrappedStyled(out, prefix, continuation, value, nil)
}

// writeWrappedStyled wraps first and colours after, so the escapes never count
// towards the width. The indentation stays uncoloured.
func writeWrappedStyled(out *bytes.Buffer, prefix, continuation, value string, style func(string) string) {
	words := strings.Fields(value)
	if len(words) == 0 {
		return
	}
	emit := func(line string) {
		if style != nil {
			body := strings.TrimLeft(line, " ")
			line = line[:len(line)-len(body)] + style(body)
		}
		out.WriteString(line + "\n")
	}
	line, width := prefix, displayWidth(prefix)
	for i, word := range words {
		if i > 0 {
			if width+1+displayWidth(word) > tableWidth {
				emit(line)
				line, width = continuation, displayWidth(continuation)
			} else {
				line, width = line+" ", width+1
			}
		}
		for _, chunk := range split(word, tableWidth-displayWidth(continuation)) {
			if width+displayWidth(chunk) > tableWidth {
				emit(line)
				line, width = continuation, displayWidth(continuation)
			}
			line, width = line+chunk, width+displayWidth(chunk)
		}
	}
	emit(line)
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
