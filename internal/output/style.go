package output

import "strings"

// Palette is the human views' colour. It is the tool's own decoration around
// text whose layout is already decided: every escape is added after wrapping
// and padding, so a coloured view and a plain one break and align in the same
// places, and nothing here reaches the JSON, which never carries colour.
//
// The CLI turns it on only for a terminal that has not opted out with
// NO_COLOR or TERM=dumb. Untrusted Azure text is never given a colour of its
// own, so it cannot pass for the tool's voice.
type Palette struct{ on bool }

// NewPalette returns a palette that colours when on is true and is a no-op
// otherwise.
func NewPalette(on bool) Palette { return Palette{on: on} }

const (
	reset    = "\x1b[0m"
	sgrBold  = "1"
	sgrDim   = "2"
	sgrRed   = "31"
	sgrGreen = "32"
	sgrAmber = "33"
	sgrBlue  = "34"
	sgrCyan  = "36"
	sgrClay  = "38;5;173"
)

func (p Palette) paint(value string, codes ...string) string {
	if !p.on || value == "" {
		return value
	}
	return "\x1b[" + strings.Join(codes, ";") + "m" + value + reset
}

// The roles the design assigns: bold for what a reader acts on, dim for
// provenance, red for what blocks a delete, amber for what a person has to
// judge, green for silence, blue for state, cyan for what to do next and clay
// for the tool's own prompt and spinner.

// Bold marks what a reader acts on.
func (p Palette) Bold(s string) string { return p.paint(s, sgrBold) }

// Dim marks provenance and secondary text.
func (p Palette) Dim(s string) string { return p.paint(s, sgrDim) }

// Red marks what blocks a delete.
func (p Palette) Red(s string) string { return p.paint(s, sgrBold, sgrRed) }

// Amber marks what a person has to judge.
func (p Palette) Amber(s string) string { return p.paint(s, sgrBold, sgrAmber) }

// Green marks silence: signals that looked and found nothing.
func (p Palette) Green(s string) string { return p.paint(s, sgrGreen) }

// Blue marks a state, such as a cordon.
func (p Palette) Blue(s string) string { return p.paint(s, sgrBold, sgrBlue) }

// Cyan marks what to do next.
func (p Palette) Cyan(s string) string { return p.paint(s, sgrCyan) }

// Clay marks the tool's own prompt and spinner.
func (p Palette) Clay(s string) string { return p.paint(s, sgrBold, sgrClay) }

// Pill is a verdict or state as a solid block, the first thing the eye lands
// on. Plain, it is the same text between spaces, so the layout is identical.
func (p Palette) Pill(kind, text string) string {
	block := " " + text + " "
	switch kind {
	case "no", "error":
		return p.paint(block, sgrBold, "97", "41")
	case "tentative":
		return p.paint(block, sgrBold, "30", "43")
	case "yes":
		return p.paint(block, sgrBold, "30", "42")
	case "cordon":
		return p.paint(block, sgrBold, "97", "44")
	default:
		return p.paint(block, sgrBold, "97", "100")
	}
}

// style returns a line styler for writeWrappedStyled, or nil when colour is
// off.
func (p Palette) style(paint func(string) string) func(string) string {
	if !p.on {
		return nil
	}
	return paint
}

// Colored turns the table view's colour on.
func Colored() ViewOption { return func(v *View) { v.Color = true } }

// CellWidth is how many terminal columns a string takes: two for an emoji or
// an East Asian wide character, one for everything else, including the box,
// arrow and tree glyphs the views draw with. It is what aligns a box's right
// edge; wrapping keeps its own, more conservative, count.
func CellWidth(s string) int {
	width := 0
	for _, r := range s {
		switch {
		case r == 0xFE0F || r == 0x200D:
			// Variation selectors and joiners take no column of their own.
		case wide(r):
			width += 2
		default:
			width++
		}
	}
	return width
}

func wide(r rune) bool {
	switch {
	case r >= 0x1F000:
		return true
	case r == 0x26D4, r == 0x2705, r == 0x26AA, r == 0x23F3, r == 0x26A1, r == 0x274C, r == 0x2753:
		return true
	case r >= 0x1100 && r <= 0x115F, r >= 0x2E80 && r <= 0xA4CF, r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF, r >= 0xFE30 && r <= 0xFE4F, r >= 0xFF00 && r <= 0xFF60, r >= 0xFFE0 && r <= 0xFFE6:
		return true
	}
	return false
}

// Box draws a rounded frame around lines of plain text, styling each with the
// matching paint function after it is padded. A line too wide for the
// terminal leaves the frame open on the right rather than being cut: the
// views show everything the report carries.
func (p Palette) Box(lines []string, paints []func(string) string, maxWidth int) string {
	inner := 0
	for _, line := range lines {
		if w := CellWidth(line); w > inner {
			inner = w
		}
	}
	inner += 4
	closed := inner+2 <= maxWidth
	if !closed {
		inner = maxWidth - 2
	}
	var b strings.Builder
	b.WriteString(p.Dim("╭"+strings.Repeat("─", inner)+"╮") + "\n")
	for i, line := range lines {
		styled := line
		if i < len(paints) && paints[i] != nil {
			styled = paints[i](line)
		}
		pad := inner - 2 - CellWidth(line)
		if !closed || pad < 0 {
			b.WriteString(p.Dim("│") + "  " + styled + "\n")
			continue
		}
		b.WriteString(p.Dim("│") + "  " + styled + strings.Repeat(" ", pad) + p.Dim("│") + "\n")
	}
	b.WriteString(p.Dim("╰"+strings.Repeat("─", inner)+"╯") + "\n")
	return b.String()
}
