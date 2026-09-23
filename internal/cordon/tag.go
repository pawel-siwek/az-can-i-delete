// Package cordon holds the scream test: the azcid state tag, the type gate,
// the local history file and the read-only status of a cordon.
//
// Nothing in this file writes to Azure. The tag is the only record a cordon
// leaves on the resource, and it is read far more often than it is written —
// by status, by uncordon, by check and by the MCP server — so its grammar is
// strict: a value that does not parse is never guessed at (SPEC appendix D).
package cordon

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TagKey is the one tag a cordon writes.
const TagKey = "azcid"

// Limits of the v1 grammar.
const (
	MaxTagBytes   = 200
	MaxSlots      = 4
	MinWindowDays = 1
	MaxWindowDays = 30
	// DefaultWindowDays is the cordon window when nobody chose one. It is not
	// the check window: a scream test is short on purpose.
	DefaultWindowDays = 7
)

// Mode is what the cordon changed.
type Mode string

// The two v0.1 modes.
const (
	// ModePNA sets a storage account's publicNetworkAccess to Disabled.
	ModePNA Mode = "pna"
	// ModeStop stops an App Service site and every slot.
	ModeStop Mode = "stop"
)

// Slot states the grammar allows.
const (
	Running = "Running"
	Stopped = "Stopped"
)

// The priors a pna cordon may restore.
const (
	PriorEnabled            = "Enabled"
	PriorSecuredByPerimeter = "SecuredByPerimeter"
)

// State is a parsed azcid value.
type State struct {
	Mode       Mode
	Since      time.Time
	By         string
	Prior      string
	WindowDays int
	// Slots keeps the order the tag gave, which is name order when this tool
	// wrote it. Only a stop cordon carries slots.
	Slots []Slot
}

// Slot is one deployment slot's state before the cordon.
type Slot struct {
	Name  string
	State string
}

// ErrCorrupt marks a value that is present and does not parse. A corrupt tag
// is never repaired or reinterpreted: its prior state is unknown, and the only
// honest answer is the manual commands.
var ErrCorrupt = errors.New("the azcid tag does not match the v1 grammar")

var (
	oidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	slotNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,40}$`)
	windowPattern   = regexp.MustCompile(`^[0-9]{1,2}$`)
	timePattern     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// timeLayout is the grammar's timestamp: seconds, UTC, a literal Z.
const timeLayout = "2006-01-02T15:04:05Z"

// Parse reads an azcid value. Key order is fixed, every key is required except
// the slots, and anything the grammar does not admit is ErrCorrupt.
func Parse(value string) (State, error) {
	if len(value) > MaxTagBytes {
		return State{}, fmt.Errorf("%w: longer than %d bytes", ErrCorrupt, MaxTagBytes)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return State{}, fmt.Errorf("%w: not printable ASCII", ErrCorrupt)
		}
	}
	fields := strings.Split(value, ";")
	keys := []string{"v", "m", "t", "by", "p", "w"}
	if len(fields) != len(keys) && len(fields) != len(keys)+1 {
		return State{}, fmt.Errorf("%w: expected %d or %d fields", ErrCorrupt, len(keys), len(keys)+1)
	}
	values := make([]string, len(fields))
	for i, field := range fields {
		want := "s"
		if i < len(keys) {
			want = keys[i]
		}
		key, val, ok := strings.Cut(field, "=")
		if !ok || key != want {
			return State{}, fmt.Errorf("%w: field %d must be %s=", ErrCorrupt, i+1, want)
		}
		values[i] = val
	}
	if values[0] != "1" {
		return State{}, fmt.Errorf("%w: unknown version", ErrCorrupt)
	}
	var state State
	switch Mode(values[1]) {
	case ModePNA, ModeStop:
		state.Mode = Mode(values[1])
	default:
		return State{}, fmt.Errorf("%w: unknown mode", ErrCorrupt)
	}
	if !timePattern.MatchString(values[2]) {
		return State{}, fmt.Errorf("%w: timestamp is not UTC seconds", ErrCorrupt)
	}
	since, err := time.Parse(timeLayout, values[2])
	if err != nil {
		return State{}, fmt.Errorf("%w: timestamp is not a valid date", ErrCorrupt)
	}
	state.Since = since
	if !oidPattern.MatchString(values[3]) {
		return State{}, fmt.Errorf("%w: by is not a lower-case object id", ErrCorrupt)
	}
	state.By = values[3]
	if !validPrior(state.Mode, values[4]) {
		return State{}, fmt.Errorf("%w: prior does not belong to the mode", ErrCorrupt)
	}
	state.Prior = values[4]
	if !windowPattern.MatchString(values[5]) {
		return State{}, fmt.Errorf("%w: window is not one or two digits", ErrCorrupt)
	}
	state.WindowDays, _ = strconv.Atoi(values[5])
	if state.WindowDays < MinWindowDays || state.WindowDays > MaxWindowDays {
		return State{}, fmt.Errorf("%w: window is outside %d-%d days", ErrCorrupt, MinWindowDays, MaxWindowDays)
	}
	if len(values) == len(keys)+1 {
		if state.Mode != ModeStop {
			return State{}, fmt.Errorf("%w: only a stop cordon records slots", ErrCorrupt)
		}
		slots, slotErr := parseSlots(values[6])
		if slotErr != nil {
			return State{}, slotErr
		}
		state.Slots = slots
	}
	return state, nil
}

func parseSlots(value string) ([]Slot, error) {
	entries := strings.Split(value, ",")
	if len(entries) > MaxSlots {
		return nil, fmt.Errorf("%w: more than %d slots", ErrCorrupt, MaxSlots)
	}
	slots := make([]Slot, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		name, state, ok := strings.Cut(entry, ":")
		if !ok || !slotNamePattern.MatchString(name) || (state != Running && state != Stopped) {
			return nil, fmt.Errorf("%w: slot entry is not name:Running or name:Stopped", ErrCorrupt)
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("%w: slot listed twice", ErrCorrupt)
		}
		seen[strings.ToLower(name)] = true
		slots = append(slots, Slot{Name: name, State: state})
	}
	return slots, nil
}

func validPrior(mode Mode, prior string) bool {
	switch mode {
	case ModePNA:
		return prior == PriorEnabled || prior == PriorSecuredByPerimeter
	case ModeStop:
		// A stopped site is refused before it is cordoned, so Running is the
		// only prior a stop cordon can have.
		return prior == Running
	}
	return false
}

// Format renders the value in the grammar's fixed key order. It refuses
// anything Parse would refuse, so a tag this tool writes always reads back.
func (s State) Format() (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "v=1;m=%s;t=%s;by=%s;p=%s;w=%d", s.Mode, s.Since.UTC().Format(timeLayout), s.By, s.Prior, s.WindowDays)
	if len(s.Slots) > 0 {
		b.WriteString(";s=")
		for i, slot := range s.Slots {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(slot.Name + ":" + slot.State)
		}
	}
	value := b.String()
	if _, err := Parse(value); err != nil {
		return "", err
	}
	return value, nil
}

// Remaining is how much of the cordon window is left at now. It is never
// negative: an expired cordon is still a cordon until somebody uncordons it.
func (s State) Remaining(now time.Time) time.Duration {
	left := s.Since.Add(time.Duration(s.WindowDays) * 24 * time.Hour).Sub(now)
	if left < 0 {
		return 0
	}
	return left
}
