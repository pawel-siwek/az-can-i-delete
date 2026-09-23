package cordon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HomeEnv overrides where the history file lives.
const HomeEnv = "AZCID_HOME"

// Entry is one line of history.jsonl (SPEC appendix E section 7.8).
type Entry struct {
	TS       time.Time         `json:"ts"`
	Action   string            `json:"action"`
	ID       string            `json:"id"`
	Mode     Mode              `json:"mode"`
	Prior    string            `json:"prior"`
	OID      string            `json:"oid"`
	Slots    map[string]string `json:"slots,omitempty"`
	Tag      string            `json:"tag"`
	TagOwner string            `json:"tagOwner,omitempty"`
}

// The two history actions.
const (
	ActionCordon   = "cordon"
	ActionUncordon = "uncordon"
)

// History is the local journal. It is this machine's memory of what it did,
// not Azure's: a cordon applied from somewhere else is not in it.
type History struct {
	Path string
}

// DefaultHistory resolves $AZCID_HOME/history.jsonl, else
// ~/.az-can-i-delete/history.jsonl.
func DefaultHistory() (History, error) {
	if home := os.Getenv(HomeEnv); home != "" {
		return History{Path: filepath.Join(home, "history.jsonl")}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return History{}, fmt.Errorf("locating the history file: %w", err)
	}
	return History{Path: filepath.Join(home, ".az-can-i-delete", "history.jsonl")}, nil
}

// Append writes one entry. The file is created 0600: it records who cordoned
// what, which is nobody else's business on a shared machine.
func (h History) Append(entry Entry) error {
	if err := os.MkdirAll(filepath.Dir(h.Path), 0o700); err != nil {
		return fmt.Errorf("creating the history directory: %w", err)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(h.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the path is this tool's own history file
	if err != nil {
		return fmt.Errorf("opening the history file: %w", err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("writing the history file: %w", err)
	}
	return file.Close()
}

// ErrNoHistory means the journal has no cordon for the resource.
var ErrNoHistory = errors.New("the local history has no cordon for this resource")

// LatestCordon returns the newest cordon entry for id, provided no uncordon
// came after it. A line that does not parse is skipped rather than trusted:
// the journal is a convenience, and a damaged line must not become a prior.
func (h History) LatestCordon(id string) (Entry, error) {
	file, err := os.Open(h.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Entry{}, ErrNoHistory
	}
	if err != nil {
		return Entry{}, fmt.Errorf("opening the history file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var latest *Entry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry Entry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || !strings.EqualFold(entry.ID, id) {
			continue
		}
		switch entry.Action {
		case ActionCordon:
			latest = &entry
		case ActionUncordon:
			latest = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return Entry{}, fmt.Errorf("reading the history file: %w", err)
	}
	if latest == nil {
		return Entry{}, ErrNoHistory
	}
	return *latest, nil
}

// State reconstructs the cordon state an entry recorded. The tag it wrote is
// the authority; the separate fields only fill in when the tag is missing.
func (e Entry) State() (State, error) {
	if e.Tag != "" {
		return Parse(e.Tag)
	}
	return State{}, fmt.Errorf("%w: the history entry recorded no tag", ErrCorrupt)
}
