//go:build !windows

package cli

import "os"

// prepareConsole has nothing to switch outside Windows: a Unix terminal
// speaks UTF-8 and ANSI already.
func prepareConsole(*os.File) bool { return true }
