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
// Nothing here is collected from Azure; it is the tool's own text. The icons
// are emoji that take two columns and need no variation selector, so a frame
// drawn around them stays square on every terminal.
var verdictBanner = map[string]struct{ icon, word, remark string }{
	"yes": {"✅", "YES",
		"No evidence of use was found. That is not proof it is unused — nothing here can see a consumer that only names this resource in code, a pipeline or a config file."},
	"no": {"⛔", "NO", ""},
	"tentative": {"🟡", "TENTATIVE",
		"I could not verify everything, so I do not know whether you can delete this. Read the evidence below and decide."},
}

// headline is the verdict in words, from the reason class rather than the
// verdict alone: a lock and a live consumer are both `no`, for different
// reasons. It is the tool's own sentence and never names the resource: a
// name is Azure's text, and it stands on its own line as an identifier.
func headline(verdict, reasonClass string) string {
	switch verdict {
	case "yes":
		return "no evidence of use found"
	case "no":
		if reasonClass == "blocked" {
			return "blocked — do not delete"
		}
		return "in use — do not delete"
	case "tentative":
		if reasonClass == "design-intent" {
			return "looks deliberately kept — a person has to decide"
		}
		return "not enough evidence to decide — a person has to look"
	}
	return ""
}

func tableOutput(items []json.RawMessage, view View) ([]byte, error) {
	var out bytes.Buffer
	p := NewPalette(view.Color)
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
			fmt.Fprintf(&out, "%s  %s\n\n", p.Pill("error", "💥 ERROR"), p.Bold(text(failure["code"])))
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

// writeVerdict is the answer, first: a frame holding the verdict and what it
// is about, then the one sentence that qualifies it.
func writeVerdict(out *bytes.Buffer, p Palette, value map[string]any) {
	verdict := text(value["verdict"])
	banner, known := verdictBanner[verdict]
	if !known {
		banner = struct{ icon, word, remark string }{"❓", strings.ToUpper(verdict), ""}
	}
	id := text(value["resourceId"])
	name := resourceName(id)
	head := headline(verdict, text(value["reasonClass"]))
	pill := " " + banner.icon + " " + banner.word + " "
	about := []string{kindOf(id)}
	if coverage, ok := value["coverage"].(map[string]any); ok {
		about = append(about, text(coverage["evaluated"])+" of "+text(coverage["total"])+" signals read")
	}
	// The name is an identifier on the pill's line, the way the canonical id
	// stands alone in the footer; it is never part of a sentence.
	indent := strings.Repeat(" ", CellWidth(pill)+2)
	lines := []string{pill + "  " + name, indent + head, indent + strings.Join(about, " · ")}
	paints := []func(string) string{
		func(string) string { return p.Pill(verdict, banner.icon+" "+banner.word) + "  " + p.Bold(name) },
		func(string) string { return indent + p.Bold(head) },
		func(line string) string { return indent + p.Dim(strings.TrimPrefix(line, indent)) },
	}
	if CellWidth(lines[0])+6 <= tableWidth {
		out.WriteString(p.Box(lines, paints, tableWidth))
	} else {
		// A name too long for the frame is wrapped rather than cut, and a
		// frame that cannot close is not drawn at all.
		fmt.Fprintf(out, "%s\n", p.Pill(verdict, banner.icon+" "+banner.word))
		writeWrappedStyled(out, "  ", "  ", name, p.style(p.Bold))
		writeWrappedStyled(out, "  ", "  ", head, p.style(p.Bold))
		writeWrappedStyled(out, "  ", "  ", strings.Join(about, " · "), p.style(p.Dim))
	}
	if banner.remark != "" {
		out.WriteString("\n")
		writeWrappedStyled(out, "  ", "  ", banner.remark, p.style(p.Dim))
	}
	if replay, _ := value["replay"].(bool); replay {
		fmt.Fprintf(out, "\n  %s\n", p.Dim("▶ RECORDED — replayed evidence, not a live assessment"))
	}
	if question := text(value["requiredHumanQuestion"]); question != "" {
		if escalate, _ := value["humanEscalation"].(bool); escalate {
			out.WriteString("\n")
			writeWrappedStyled(out, "  ? ", "    ", question, p.style(p.Amber))
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

// kinds names the analyzed types the way a person says them.
var kinds = map[string]string{
	"microsoft.storage/storageaccounts":       "Storage account",
	"microsoft.compute/disks":                 "Managed disk",
	"microsoft.compute/virtualmachines":       "Virtual machine",
	"microsoft.network/networkinterfaces":     "Network interface",
	"microsoft.network/publicipaddresses":     "Public IP",
	"microsoft.network/networksecuritygroups": "Network security group",
	"microsoft.web/sites":                     "App Service site",
	"microsoft.web/sites/slots":               "Deployment slot",
	"microsoft.web/serverfarms":               "App Service plan",
}

// kindOf reads the resource type out of the id: the provider namespace and
// every type segment after it.
func kindOf(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if !strings.EqualFold(parts[i], "providers") {
			continue
		}
		segments := []string{parts[i+1]}
		for j := i + 2; j < len(parts); j += 2 {
			segments = append(segments, parts[j])
		}
		kind := strings.ToLower(strings.Join(segments, "/"))
		if named, ok := kinds[kind]; ok {
			return named
		}
		return strings.Join(segments, "/")
	}
	return "Resource"
}

// writeFindings prints what was actually found and what could not be read.
// Everything that looked and found nothing is counted, not listed.
func writeFindings(out *bytes.Buffer, p Palette, value map[string]any) {
	evidence, _ := value["evidence"].([]any)
	var found, unreadable []map[string]any
	var skipped []string
	quiet := 0
	blocking := false
	for _, item := range evidence {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch text(row["status"]) {
		case "present":
			if decisive(row) {
				found = append(found, row)
				if text(row["tierName"]) != "DESIGN_INTENT" {
					blocking = true
				}
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
		if blocking {
			fmt.Fprintf(out, "\n  🔴 %s %s\n", p.Red("Found"), p.Dim(fmt.Sprint(len(found))))
		} else {
			fmt.Fprintf(out, "\n  🟠 %s %s\n", p.Amber("Found"), p.Dim(fmt.Sprint(len(found))))
		}
		for _, row := range found {
			mark := p.Red("✗")
			if text(row["tierName"]) == "DESIGN_INTENT" {
				mark = p.Amber("◆")
			}
			writeSignal(out, p, row, mark)
		}
	}
	if len(unreadable) > 0 {
		fmt.Fprintf(out, "\n  🟡 %s %s\n", p.Amber("Could not check"), p.Dim(fmt.Sprint(len(unreadable))))
		for _, row := range unreadable {
			writeSignal(out, p, row, p.Amber("?"))
		}
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		fmt.Fprintf(out, "\n  ⚪ %s %s\n", p.Bold("Not evaluated"), p.Dim(fmt.Sprint(len(skipped))))
		writeWrappedStyled(out, "     ", "     ", strings.Join(skipped, " · "), p.style(p.Dim))
	}
	if quiet > 0 {
		fmt.Fprintf(out, "\n  🟢 %s\n", p.Green(fmt.Sprintf("%d signals looked and found nothing", quiet)))
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

// writeSignal is one row as a small tree: the id, what it means, why it could
// not be read, and what to do.
func writeSignal(out *bytes.Buffer, p Palette, row map[string]any, mark string) {
	critical := ""
	if c, _ := row["critical"].(bool); c && text(row["status"]) == "unknown" {
		critical = " " + p.Red("‼")
	}
	code := ""
	if unknown, ok := row["unknown"].(map[string]any); ok {
		code = " " + p.Dim("("+text(unknown["code"])+")")
	}
	fmt.Fprintf(out, "  %s %s%s%s\n", mark, p.Bold(text(row["id"])), code, critical)
	writeWrappedStyled(out, "    ⎿  ", "       ", text(row["summary"]), nil)
	// The code is a category; the reason is the one thing that tells a reader
	// whether this is theirs to fix. `transient` alone sends them nowhere.
	if unknown, ok := row["unknown"].(map[string]any); ok {
		if reason := text(unknown["reason"]); reason != "" {
			writeWrappedStyled(out, "       ↳ ", "         ", reason, p.style(p.Dim))
		}
	}
	for _, step := range textList(row["nextSteps"]) {
		writeWrappedStyled(out, "       → ", "         ", step, p.style(p.Cyan))
	}
}

// writeFooter is one line of provenance and one of what else is available.
func writeFooter(out *bytes.Buffer, p Palette, value map[string]any, view View) {
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
		parts = append(parts, "age ≥ "+text(age["lowerBoundDays"])+" d")
	}
	parts = append(parts, "rules "+text(value["rulesDate"]), "v"+text(value["toolVersion"]))
	fmt.Fprintf(out, "\n  %s\n", p.Dim(strings.Join(parts, " · ")))
	if !view.Full {
		fmt.Fprintf(out, "  %s\n", p.Dim("--full every signal · -o json for machines"))
	}
	writeWrappedStyled(out, "  ", "  ", text(value["resourceId"]), p.style(p.Dim))
}

// writeEverySignal is the complete list, for --full.
func writeEverySignal(out *bytes.Buffer, p Palette, value map[string]any) {
	evidence, ok := value["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s\n", p.Bold("Evidence"))
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
