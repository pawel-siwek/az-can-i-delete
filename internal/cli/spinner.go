package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
)

// spinner is the progress line a person sees while a check reads Azure: a
// frame, what is being checked, and how many reads have finished. It counts
// what Gather really finished; it never invents steps or a percentage.
//
// It writes only to a terminal on stderr, and clears its line before the
// result prints, so a pipe, a log or -o json sees nothing of it.
type spinner struct {
	w       io.Writer
	p       output.Palette
	mu      sync.Mutex
	label   string
	done    int
	last    string
	stop    chan struct{}
	stopped chan struct{}
}

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// startSpinner returns a spinner on errOut when it is a terminal that can draw
// one, and nil otherwise. A nil spinner's methods do nothing.
func startSpinner(errOut io.Writer, color bool) *spinner {
	if os.Getenv("TERM") == "dumb" || os.Getenv("CI") != "" {
		return nil
	}
	file, ok := terminalFile(errOut)
	if !ok || !prepareConsole(file) {
		return nil
	}
	s := &spinner{w: file, p: output.NewPalette(color), stop: make(chan struct{}), stopped: make(chan struct{})}
	go s.run()
	return s
}

func (s *spinner) run() {
	defer close(s.stopped)
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; ; i++ {
		s.mu.Lock()
		line := fmt.Sprintf("%s %s %s", s.p.Clay(frames[i%len(frames)]), s.label,
			s.p.Dim(fmt.Sprintf("· %d reads done · %s", s.done, s.last)))
		s.mu.Unlock()
		_, _ = fmt.Fprintf(s.w, "\r\x1b[2K%s", line)
		select {
		case <-s.stop:
			_, _ = fmt.Fprint(s.w, "\r\x1b[2K")
			return
		case <-ticker.C:
		}
	}
}

// track starts counting for target n of total and returns a context whose
// reads the spinner counts. The label is the tool's own words: a resource
// name is Azure's text and never part of a sentence this tool says
// (ADR-0007), on stderr as much as anywhere.
func (s *spinner) track(ctx context.Context, n, total int) context.Context {
	if s == nil {
		return ctx
	}
	label := "Checking the resource"
	if total > 1 {
		label = fmt.Sprintf("Checking resource %d of %d", n, total)
	}
	s.mu.Lock()
	s.label, s.done, s.last = label, 0, "starting"
	s.mu.Unlock()
	return collect.WithProgress(ctx, func(id string) {
		s.mu.Lock()
		s.done++
		s.last = id
		s.mu.Unlock()
	})
}

// finish clears the line and waits for the last frame, so nothing of the
// spinner is left above the result.
func (s *spinner) finish() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.stopped
}
