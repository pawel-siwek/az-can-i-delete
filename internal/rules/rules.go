// Package rules holds the embedded api-version pins every collector requests
// under. Keeping them in data rather than in call sites means a version can be
// corrected in one place, and a resource type without a pin is an unsupported
// type rather than a guess.
package rules

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var source []byte

type table struct {
	ResourceTypes map[string]string `yaml:"resourceTypes"`
	Operations    map[string]string `yaml:"operations"`
}

var (
	once   sync.Once
	loaded table
	err    error
)

func load() (table, error) {
	once.Do(func() {
		var parsed table
		if unmarshalErr := yaml.Unmarshal(source, &parsed); unmarshalErr != nil {
			err = fmt.Errorf("embedded rules are unreadable: %w", unmarshalErr)
			return
		}
		if len(parsed.ResourceTypes) == 0 || len(parsed.Operations) == 0 {
			err = fmt.Errorf("embedded rules are incomplete")
			return
		}
		loaded = parsed
	})
	return loaded, err
}

// APIVersion returns the pinned GET api-version for a full ARM resource type.
// An unpinned type has no analyzer, so the caller must refuse it.
func APIVersion(resourceType string) (string, error) {
	rules, loadErr := load()
	if loadErr != nil {
		return "", loadErr
	}
	version, ok := rules.ResourceTypes[strings.ToLower(resourceType)]
	if !ok {
		return "", fmt.Errorf("unsupported resource type %s", resourceType)
	}
	return version, nil
}

// Supported reports whether a type has a pinned api-version.
func Supported(resourceType string) bool {
	_, versionErr := APIVersion(resourceType)
	return versionErr == nil
}

// SupportedTypes lists every pinned type, for the usage message.
func SupportedTypes() []string {
	rules, loadErr := load()
	if loadErr != nil {
		return nil
	}
	types := make([]string, 0, len(rules.ResourceTypes))
	for name := range rules.ResourceTypes {
		types = append(types, name)
	}
	return types
}

// Operation returns the pinned api-version of a non-GET call such as locks,
// deny assignments, deployments, Resource Graph, the Activity Log or metrics.
func Operation(name string) (string, error) {
	rules, loadErr := load()
	if loadErr != nil {
		return "", loadErr
	}
	version, ok := rules.Operations[name]
	if !ok {
		return "", fmt.Errorf("no pinned api-version for operation %s", name)
	}
	return version, nil
}

// MustOperation is for call sites that cannot proceed without the pin; an
// unpinned operation is a build-time mistake, not a collection failure.
func MustOperation(name string) string {
	version, opErr := Operation(name)
	if opErr != nil {
		panic(opErr)
	}
	return version
}
