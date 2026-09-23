// Package kb is the storage name knowledge base: the table that recognizes a
// container, share, queue, table, account, resource group, tag or lock name as
// the work of a known Azure producer.
//
// A name is weak evidence and the package keeps it weak. Matching by name
// yields the entry's unconfirmedTier and nothing stronger; the confirmed tier
// is reached only when a caller has found the producer in configuration and
// says so. Six entries carry no usable name pattern at all and are matched
// only by such a confirmation.
package kb

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed kb.yaml
var source []byte

// Entry is one row of the knowledge base.
type Entry struct {
	ID              string   `yaml:"id"`
	Kind            string   `yaml:"kind"`
	Regex           string   `yaml:"regex"`
	Mechanism       bool     `yaml:"mechanism"`
	Producer        string   `yaml:"producer"`
	Tier            string   `yaml:"tier"`
	UnconfirmedTier string   `yaml:"unconfirmedTier"`
	Confirm         string   `yaml:"confirm"`
	Freshness       string   `yaml:"freshness"`
	Confidence      string   `yaml:"confidence"`
	Status          string   `yaml:"status"`
	SourceURL       string   `yaml:"source_url"`
	Examples        []string `yaml:"examples"`
	Counterexamples []string `yaml:"counterexamples"`
	New             bool     `yaml:"new"`

	compiled *regexp.Regexp
}

// Matches reports whether this entry's pattern covers the name. A mechanism
// entry matches no name at all: it has no pattern worth the word, and saying
// otherwise would turn "any share" into evidence.
func (e Entry) Matches(name string) bool {
	if e.Mechanism || e.compiled == nil {
		return false
	}
	return e.compiled.MatchString(name)
}

type table struct {
	SchemaVersion int     `yaml:"schemaVersion"`
	RulesDate     string  `yaml:"rulesDate"`
	Entries       []Entry `yaml:"entries"`
}

var (
	once    sync.Once
	loaded  table
	loadErr error
)

// kinds the knowledge base recognizes. A row with any other kind would never
// be consulted, which is a mistake in the data rather than a silent no-match.
var kinds = map[string]bool{
	"container": true, "blobPrefix": true, "share": true, "queue": true,
	"table": true, "accountName": true, "rgName": true, "tag": true, "lockName": true,
}

// tiers a row may name, in the verdict's own order.
var tiers = map[string]bool{
	"BLOCKER": true, "HARD_DEPENDENCY": true, "LIVE_ACTIVITY": true,
	"DESIGN_INTENT": true, "OBSERVED_IDLE": true, "INFO": true,
}

func load() (table, error) {
	once.Do(func() {
		var parsed table
		if err := yaml.Unmarshal(source, &parsed); err != nil {
			loadErr = fmt.Errorf("the embedded knowledge base is unreadable: %w", err)
			return
		}
		if parsed.SchemaVersion != 1 {
			loadErr = fmt.Errorf("the embedded knowledge base is schema %d, not 1", parsed.SchemaVersion)
			return
		}
		if len(parsed.Entries) == 0 {
			loadErr = fmt.Errorf("the embedded knowledge base is empty")
			return
		}
		seen := make(map[string]bool, len(parsed.Entries))
		for index := range parsed.Entries {
			entry := &parsed.Entries[index]
			if err := validate(entry, seen); err != nil {
				loadErr = err
				return
			}
		}
		loaded = parsed
	})
	return loaded, loadErr
}

// validate holds one row to the loader rules of SPEC section 10.6. A row that
// fails any of them makes the whole base refuse to load: a knowledge base that
// silently drops rows would answer "no match" for a producer it knows.
func validate(entry *Entry, seen map[string]bool) error {
	switch {
	case entry.ID == "":
		return fmt.Errorf("a knowledge base entry has no id")
	case seen[entry.ID]:
		return fmt.Errorf("%s: duplicate id", entry.ID)
	case !kinds[entry.Kind]:
		return fmt.Errorf("%s: unknown kind %q", entry.ID, entry.Kind)
	case !tiers[entry.Tier]:
		return fmt.Errorf("%s: unknown tier %q", entry.ID, entry.Tier)
	case !tiers[entry.UnconfirmedTier]:
		return fmt.Errorf("%s: unknown unconfirmedTier %q", entry.ID, entry.UnconfirmedTier)
	case entry.Producer == "":
		return fmt.Errorf("%s: no producer, so a match could not say what made the name", entry.ID)
	case entry.Confirm == "":
		return fmt.Errorf("%s: no confirm text, so a match could not say what would confirm it", entry.ID)
	}
	seen[entry.ID] = true

	// mechanism true means exactly ".*" and the other way round: a row that
	// matches everything must be declared as one, and a declared mechanism must
	// not carry a pattern somebody could mistake for a real one.
	if entry.Mechanism != (entry.Regex == ".*") {
		return fmt.Errorf("%s: mechanism is %v but the pattern is %q; mechanism means exactly `.*`",
			entry.ID, entry.Mechanism, entry.Regex)
	}
	compiled, err := regexp.Compile(entry.Regex)
	if err != nil {
		return fmt.Errorf("%s: pattern does not compile: %w", entry.ID, err)
	}
	if !entry.Mechanism {
		entry.compiled = compiled
	}
	// A mechanism entry may still carry examples. They are documentation of
	// what the producer's container tends to be called, never a pattern: the
	// example tests skip them, because a mechanism matches no name at all.
	return nil
}

// Date is the day the knowledge base was last reviewed.
func Date() string {
	base, err := load()
	if err != nil {
		return ""
	}
	return base.RulesDate
}

// Entries is the knowledge base in file order, which is match order.
func Entries() ([]Entry, error) {
	base, err := load()
	if err != nil {
		return nil, err
	}
	return base.Entries, nil
}

// Lookup returns the first entry whose pattern matches this name for this
// kind. File order is the precedence: a specific entry precedes the generic
// one it would otherwise be shadowed by.
func Lookup(kind, name string) (Entry, bool, error) {
	base, err := load()
	if err != nil {
		return Entry{}, false, err
	}
	if name == "" {
		return Entry{}, false, nil
	}
	for _, entry := range base.Entries {
		if entry.Kind == kind && entry.Matches(name) {
			return entry, true, nil
		}
	}
	return Entry{}, false, nil
}

// Mechanisms returns the entries of a kind that carry no name pattern. They
// are reachable only through a caller that has already confirmed the producer.
func Mechanisms(kind string) ([]Entry, error) {
	base, err := load()
	if err != nil {
		return nil, err
	}
	var found []Entry
	for _, entry := range base.Entries {
		if entry.Mechanism && entry.Kind == kind {
			found = append(found, entry)
		}
	}
	return found, nil
}

// Tag matches a tag key. Tag entries match on the key alone; what the value
// has to be is the entry's confirm text, checked by ValueConfirms.
func Tag(key string) (Entry, bool, error) {
	return Lookup("tag", strings.TrimSpace(key))
}

// falsey are the values that make a protective tag mean nothing.
var falsey = map[string]bool{"false": true, "no": true, "0": true, "": true}

// ValueConfirms reports whether a tag's value satisfies its entry's confirm
// rule, and whether such a rule is implemented at all.
//
// Three entries turn on their value: a Cloud Shell marker, a protection tag
// that somebody may have set to false, and an expiry tag whose value has to be
// a date. Every other entry's confirm text describes a query against Azure
// rather than a property of the value, so known is false and a caller must not
// read that as confirmation — an unimplemented check is not a passed one.
//
// The confirm text is prose for a human. These rules are code that implements
// what the prose says; nothing here parses the prose itself.
func ValueConfirms(id, value string) (confirmed, known bool) {
	trimmed := strings.TrimSpace(value)
	switch id {
	case "tag.cloudshell":
		return strings.EqualFold(trimmed, "azure-cloud-shell"), true
	case "tag.protect-generic":
		return !falsey[strings.ToLower(trimmed)], true
	case "tag.expiry-generic":
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02", "2006-01-02T15:04:05"} {
			if _, err := time.Parse(layout, trimmed); err == nil {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}
