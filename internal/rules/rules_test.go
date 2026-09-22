package rules_test

import (
	"regexp"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

var apiVersion = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$`)

func TestPinnedVersions(t *testing.T) {
	cases := map[string]string{
		"Microsoft.Compute/disks":           "2026-03-02",
		"microsoft.storage/storageAccounts": "2026-04-01",
		"Microsoft.Web/sites/slots":         "2025-05-01",
	}
	for resourceType, want := range cases {
		got, err := rules.APIVersion(resourceType)
		if err != nil || got != want {
			t.Errorf("APIVersion(%s) = %q, %v; want %q", resourceType, got, err, want)
		}
	}
	if _, err := rules.APIVersion("Microsoft.Sql/servers"); err == nil {
		t.Error("an unpinned type must be refused rather than guessed")
	}
	if rules.Supported("Microsoft.Sql/servers") || !rules.Supported("Microsoft.Compute/disks") {
		t.Error("Supported must follow the pins")
	}
}

func TestOperationVersions(t *testing.T) {
	for name, want := range map[string]string{
		"locks":           "2020-05-01",
		"denyAssignments": "2022-04-01",
		"deployments":     "2026-06-01",
		"resourceGraph":   "2024-04-01",
		"activityLog":     "2015-04-01",
		"metrics":         "2024-02-01",
	} {
		got, err := rules.Operation(name)
		if err != nil || got != want {
			t.Errorf("Operation(%s) = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := rules.Operation("invented"); err == nil {
		t.Error("an unpinned operation must be an error")
	}
}

func TestEveryPinIsAnAPIVersion(t *testing.T) {
	types := rules.SupportedTypes()
	if len(types) < 10 {
		t.Fatalf("the seven v0.1 analyzer types and their relatives must all be pinned, got %d", len(types))
	}
	for _, resourceType := range types {
		version, err := rules.APIVersion(resourceType)
		if err != nil || !apiVersion.MatchString(version) {
			t.Errorf("%s is pinned to %q, which is not an api-version", resourceType, version)
		}
	}
}
