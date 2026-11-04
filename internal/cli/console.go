package cli

import (
	"io"
	"os"

	"golang.org/x/term"
)

// terminalFile returns the writer's file when it is a terminal.
func terminalFile(w io.Writer) (*os.File, bool) {
	file, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, false
	}
	return file, true
}

// colorFor decides whether a human view written to w is coloured. A
// terminal gets colour unless it opted out (https://no-color.org) or cannot
// draw it; CLICOLOR_FORCE or FORCE_COLOR asks for it where no terminal is
// detected, such as a recording or a CI log that renders ANSI.
func colorFor(w io.Writer) bool {
	// A terminal is prepared whatever is decided about colour: on Windows
	// that is also what makes UTF-8 glyphs readable, which NO_COLOR does not
	// opt out of, and what makes forced colour render rather than print.
	file, terminal := terminalFile(w)
	ready := terminal && prepareConsole(file)
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if forced("CLICOLOR_FORCE") || forced("FORCE_COLOR") {
		return !terminal || ready
	}
	return ready
}

func forced(name string) bool {
	value := os.Getenv(name)
	return value != "" && value != "0" && value != "false"
}
