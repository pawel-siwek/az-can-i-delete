// Command driftcheck compares the checked-out change against a base revision
// and reports where the code and the documents that govern it have come apart.
//
// It exits 1 on a blocking finding, so a pull request cannot be merged past a
// decision record edited to agree with new code, or a status table that starts
// claiming a component exists before its tests do. Everything else it finds is
// printed for a human and does not fail the check.
//
// It reads git and nothing else: no network, no credentials, no model. A
// reviewer that cannot run is not a reviewer that approved, so a failure to
// compare is an error rather than a silent pass.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/drift"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: driftcheck <base-revision>")
		os.Exit(2)
	}
	findings, err := run(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "the change could not be compared against %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	blocking := 0
	for _, finding := range findings {
		if finding.Blocking {
			blocking++
			fmt.Printf("::error file=%s::%s\n", finding.Path, finding.Detail)
		} else {
			fmt.Printf("::warning file=%s::%s\n", finding.Path, finding.Detail)
		}
		fmt.Println(finding)
	}

	switch {
	case blocking > 0:
		fmt.Printf("\nNOT OK — %d blocking finding(s), %d note(s).\n", blocking, len(findings)-blocking)
		os.Exit(1)
	case len(findings) > 0:
		fmt.Printf("\nOK — no blocking findings; %d note(s) for a human to weigh.\n", len(findings))
	default:
		fmt.Println("OK — the change and the documents agree.")
	}
}

// run collects the changed files on both sides of the comparison.
func run(base string) ([]drift.Finding, error) {
	names, err := git("diff", "--name-only", "--diff-filter=ACMDR", base+"...HEAD")
	if err != nil {
		return nil, err
	}
	var changes []drift.Change
	for _, path := range strings.Split(strings.TrimSpace(names), "\n") {
		if path == "" {
			continue
		}
		// A file missing on one side reads as empty, which is what Change means
		// by added or deleted. A read error on one side is not an absence, so
		// only the "does not exist" case is allowed to be empty.
		before, err := show(base, path)
		if err != nil {
			return nil, err
		}
		after, err := show("HEAD", path)
		if err != nil {
			return nil, err
		}
		changes = append(changes, drift.Change{Path: path, Before: before, After: after})
	}
	return drift.Check(changes), nil
}

// show returns a file's contents at a revision, or empty if it is not there.
func show(revision, path string) (string, error) {
	body, err := git("show", revision+":"+path)
	if err == nil {
		return body, nil
	}
	exists, listErr := git("ls-tree", "-r", "--name-only", revision, "--", path)
	if listErr != nil {
		return "", listErr
	}
	if strings.TrimSpace(exists) == "" {
		return "", nil // genuinely absent at this revision
	}
	return "", err
}

func git(args ...string) (string, error) {
	command := exec.Command("git", args...)
	var stderr strings.Builder
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
