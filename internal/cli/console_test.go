package cli

import (
	"bytes"
	"testing"
)

// Colour follows https://no-color.org: a terminal gets it, NO_COLOR and a
// dumb terminal take it away, and CLICOLOR_FORCE or FORCE_COLOR asks for it
// where no terminal is detected. A buffer is never a terminal.
func TestColourFollowsTheTerminalAndItsOptOuts(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"FORCE_COLOR": "1"}, true},
		{map[string]string{"CLICOLOR_FORCE": "1"}, true},
		{map[string]string{"FORCE_COLOR": "0"}, false},
		{map[string]string{"FORCE_COLOR": "1", "NO_COLOR": "1"}, false},
		{map[string]string{"FORCE_COLOR": "1", "TERM": "dumb"}, false},
	} {
		for _, name := range []string{"NO_COLOR", "TERM", "CLICOLOR_FORCE", "FORCE_COLOR"} {
			t.Setenv(name, tc.env[name])
		}
		if got := colorFor(&bytes.Buffer{}); got != tc.want {
			t.Errorf("env %v: colour = %t, want %t", tc.env, got, tc.want)
		}
	}
}

// The spinner draws only on a terminal; a buffer, which is what every
// pipe and test looks like, gets none, and a nil spinner is safe to use.
func TestTheSpinnerStaysOffAPipe(t *testing.T) {
	var errOut bytes.Buffer
	s := startSpinner(&errOut, true)
	if s != nil {
		t.Fatal("a spinner started on a buffer")
	}
	ctx := s.track(t.Context(), 1, 1)
	if ctx == nil {
		t.Fatal("a nil spinner must hand the context back")
	}
	s.finish()
	if errOut.Len() != 0 {
		t.Fatalf("wrote %q to a pipe", errOut.String())
	}
}
