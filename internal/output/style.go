package output

// The table view's colour. It is the tool's own decoration around text whose
// layout is already decided: every escape is added after wrapping, so a
// coloured line and a plain one break in the same places, and nothing here
// touches the JSON, which never carries a colour.
//
// Colour is on only when the caller asks for it (Colored), which the CLI does
// for a terminal that has not opted out with NO_COLOR.
type painter bool

const (
	reset     = "\x1b[0m"
	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	red       = "\x1b[31m"
	green     = "\x1b[32m"
	yellow    = "\x1b[33m"
	blue      = "\x1b[34m"
	magenta   = "\x1b[35m"
	cyan      = "\x1b[36m"
	onRed     = "\x1b[1;97;41m"
	onGreen   = "\x1b[1;30;42m"
	onYellow  = "\x1b[1;30;43m"
	onMagenta = "\x1b[1;97;45m"
)

func (p painter) paint(codes, value string) string {
	if !p || value == "" {
		return value
	}
	return codes + value + reset
}

// style returns a line styler for writeWrappedAt, or nil when colour is off.
func (p painter) style(codes string) func(string) string {
	if !p {
		return nil
	}
	return func(line string) string { return p.paint(codes, line) }
}

// badge is the verdict as a powerline-style block: the answer is the first
// thing the eye lands on.
func (p painter) badge(verdict, icon, word string) string {
	if !p {
		return icon + "  " + word
	}
	background := onMagenta
	switch verdict {
	case "yes":
		background = onGreen
	case "no":
		background = onRed
	case "tentative":
		background = onYellow
	}
	return p.paint(background, " "+icon+" "+word+" ")
}

// Colored turns the table view's colour on. The CLI asks for it only when
// standard output is a terminal and NO_COLOR is not set.
func Colored() ViewOption { return func(v *View) { v.Color = true } }
