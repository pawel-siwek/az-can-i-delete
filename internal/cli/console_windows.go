//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

// codePageUTF8 is Windows code page 65001.
const codePageUTF8 = 65001

// prepareConsole switches a Windows console to UTF-8 output and ANSI escape
// processing. Without the first, every emoji and box glyph arrives as code
// page garbage; without the second, every colour arrives as visible escape
// codes. A console that refuses either gets no colour.
func prepareConsole(file *os.File) bool {
	_ = windows.SetConsoleOutputCP(codePageUTF8)
	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
