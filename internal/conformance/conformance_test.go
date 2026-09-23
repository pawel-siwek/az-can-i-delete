package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// root is the repository, relative to this package.
func root() string { return filepath.Join("..", "..") }

// sourceFile is one Go file the constraints are read against.
type sourceFile struct {
	path string // repository-relative, with forward slashes
	body string
	file *ast.File
	fset *token.FileSet
}

// sources walks the repository's own Go code. Test files are included only
// when withTests is set: a fixture may legitimately name a version or an
// operation that production code must not.
func sources(t *testing.T, withTests bool) []sourceFile {
	t.Helper()
	var found []sourceFile
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root(), dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !withTests && strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path) //nolint:gosec // the path comes from walking this repository
			if readErr != nil {
				return readErr
			}
			fset := token.NewFileSet()
			parsed, parseErr := parser.ParseFile(fset, path, body, parser.SkipObjectResolution)
			if parseErr != nil {
				return parseErr
			}
			relative, relErr := filepath.Rel(root(), path)
			if relErr != nil {
				return relErr
			}
			found = append(found, sourceFile{
				path: filepath.ToSlash(relative),
				body: string(body),
				file: parsed,
				fset: fset,
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) == 0 {
		t.Fatal("no Go source was found, so these constraints checked nothing")
	}
	return found
}

// imports reports the import paths of a file.
func imports(file sourceFile) []string {
	var paths []string
	for _, spec := range file.file.Imports {
		paths = append(paths, strings.Trim(spec.Path.Value, `"`))
	}
	return paths
}

// under reports whether a file lives in any of these package directories.
func under(file sourceFile, dirs ...string) bool {
	for _, dir := range dirs {
		if strings.HasPrefix(file.path, dir+"/") {
			return true
		}
	}
	return false
}

// ADR-0003: the verdict engine is a function of its inputs. A clock read or a
// network call here means a verdict cannot be reproduced from the evidence
// that produced it.
func TestTheVerdictEngineReadsNoClockAndNoNetwork(t *testing.T) {
	pure := []string{"internal/verdict", "internal/age"}
	banned := map[string]string{
		"net":       "a network call",
		"net/http":  "a network call",
		"math/rand": "a value that is not a function of the inputs",
	}
	for _, file := range sources(t, true) {
		if !under(file, pure...) {
			continue
		}
		for _, path := range imports(file) {
			if what, forbidden := banned[path]; forbidden {
				t.Errorf("%s imports %s, which puts %s inside the pure engine (docs/adr/0003)", file.path, path, what)
			}
		}
		ast.Inspect(file.file, func(node ast.Node) bool {
			call, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := call.X.(*ast.Ident)
			if !ok || pkg.Name != "time" {
				return true
			}
			if call.Sel.Name == "Now" || call.Sel.Name == "Since" || call.Sel.Name == "Until" {
				position := file.fset.Position(call.Pos())
				t.Errorf("%s:%d reads the clock (time.%s); the observation cutoff is an input (docs/adr/0003)",
					file.path, position.Line, call.Sel.Name)
			}
			return true
		})
	}
}

// ADR-0010: analyzers speak to the five interfaces, so every one of them is
// testable with fakes and no test needs a subscription.
func TestAnalyzersDependOnTheBoundariesNotTheSDK(t *testing.T) {
	const boundary = "github.com/pawel-siwek/az-can-i-delete/internal/azure"
	allowed := []string{"internal/azure", "internal/cli", "cmd"}
	for _, file := range sources(t, true) {
		if under(file, allowed...) {
			continue
		}
		for _, path := range imports(file) {
			if path == boundary {
				t.Errorf("%s imports the SDK adapters directly; analyzers depend on internal/collect (docs/adr/0010)", file.path)
			}
			if strings.HasPrefix(path, "github.com/Azure/azure-sdk-for-go/") {
				t.Errorf("%s imports the Azure SDK directly; only internal/azure may (docs/adr/0010)", file.path)
			}
		}
	}
}

// goReferenceLayout is the one date that is not an api-version.
const goReferenceLayout = "2006-01-02"

var apiVersion = regexp.MustCompile(`"(20\d\d-\d\d-\d\d)(-preview)?"`)

// ADR-0008: one pin per operation, in the rule table. Two copies of a version
// agree until they do not, and then a signal is collected under one and
// reported under the other.
func TestApiVersionsLiveOnlyInTheRuleTable(t *testing.T) {
	for _, file := range sources(t, false) {
		if under(file, "internal/rules") {
			continue
		}
		for _, match := range apiVersion.FindAllStringSubmatch(file.body, -1) {
			if strings.HasPrefix(match[1], goReferenceLayout) {
				continue // the Go reference time, not a version
			}
			t.Errorf("%s carries the api-version %s as a literal; pin it in internal/rules/rules.yaml and read it back (docs/adr/0008)",
				file.path, match[1])
		}
	}
}

// ADR-0006: the tool reads with the caller's own identity and acquires
// nothing. This is the constraint that keeps it approvable for a production
// subscription, so it is checked literally.
//
// Naming the operation is not performing it: the storage analyzer treats
// somebody else's `listKeys` in the Activity Log as evidence that the account
// is being used, which is exactly the kind of observation this tool exists to
// make. What is forbidden is calling it — the invocation and the request path
// below, not the word.
func TestNothingAcquiresAKeyOrASharedSecret(t *testing.T) {
	banned := []struct{ needle, why string }{
		{".ListKeys(", "acquiring an account key"},
		{`"/listKeys"`, "requesting an account key"},
		{"/listKeys?", "requesting an account key"},
		{"SharedKeyCredential", "authenticating with an account key"},
		{"GenerateUserDelegationSAS", "minting a SAS token"},
		{"ServiceSASSignatureValues", "minting a SAS token"},
	}
	for _, file := range sources(t, false) {
		for _, forbidden := range banned {
			if strings.Contains(file.body, forbidden.needle) {
				t.Errorf("%s mentions %s (%s); the tool never acquires a credential (docs/adr/0006)",
					file.path, forbidden.needle, forbidden.why)
			}
		}
	}
}

// ADR-0009: the budget is the only thing that decides how often Azure is
// called. An SDK retrying underneath it hides time and multiplies load.
func TestTheSDKDoesNotRetryBehindTheBudget(t *testing.T) {
	client, err := os.ReadFile(filepath.Join(root(), "internal", "azure", "client.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(client), "MaxRetries: -1") {
		t.Error("internal/azure/client.go no longer disables the SDK's own retries; internal/collect owns retry (docs/adr/0009)")
	}
	for _, file := range sources(t, false) {
		if under(file, "internal/azure", "internal/collect") {
			continue
		}
		if strings.Contains(file.body, "RetryOptions") || strings.Contains(file.body, "MaxRetries") {
			t.Errorf("%s configures retries outside internal/collect (docs/adr/0009)", file.path)
		}
	}
}

// ADR-0002: tiers decide. A number that stands in for confidence invites a
// threshold the reader invented.
func TestNoNumericConfidenceReachesTheVerdict(t *testing.T) {
	for _, file := range sources(t, false) {
		if !under(file, "internal/verdict", "internal/output") {
			continue
		}
		ast.Inspect(file.file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok {
				return true
			}
			kind, ok := field.Type.(*ast.Ident)
			if !ok || !isNumeric(kind.Name) {
				return true
			}
			for _, name := range field.Names {
				switch strings.ToLower(name.Name) {
				case "score", "confidence", "risk", "weight", "probability":
					position := file.fset.Position(name.Pos())
					t.Errorf("%s:%d declares a numeric %s; the verdict is tiered, never scored (docs/adr/0002)",
						file.path, position.Line, name.Name)
				}
			}
			return true
		})
	}
}

func isNumeric(name string) bool {
	switch name {
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
		return true
	}
	return false
}

// ADR-0001: no model in the engine, and nothing loaded at runtime. The
// dependency list is where that stops being true first.
func TestNoModelClientIsADependency(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(root(), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, vendor := range []string{"openai", "anthropic", "google.golang.org/genai", "cohere", "huggingface", "langchain", "ollama"} {
		if strings.Contains(strings.ToLower(string(mod)), vendor) {
			t.Errorf("go.mod depends on %s; the verdict is produced by rules, not by a model (docs/adr/0001)", vendor)
		}
	}
}

// ADR-0005: assessment reads. A mutation reachable from check would make the
// verdict the authorization for the change that follows it.
func TestTheAssessmentPathPerformsNoWrites(t *testing.T) {
	readOnly := []string{
		"internal/assess", "internal/generic", "internal/disk", "internal/network",
		"internal/storage", "internal/vm", "internal/site",
	}
	banned := []string{"http.MethodPut", "http.MethodPatch", "http.MethodDelete", "http.MethodPost"}
	for _, file := range sources(t, false) {
		if !under(file, readOnly...) {
			continue
		}
		for _, method := range banned {
			if strings.Contains(file.body, method) {
				t.Errorf("%s issues %s; assessment is read-only and cordon is a separate path (docs/adr/0005)", file.path, method)
			}
		}
	}
}

// pipeToShell matches a download piped straight into an interpreter.
var pipeToShell = regexp.MustCompile(`(?i)(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b`)

// instruction distinguishes a command somebody could paste from prose about
// the pattern. A real instruction carries a real address — a scheme or a
// variable holding one — while a discussion of the anti-pattern elides it,
// as this file and docs/adr/0014 both do. Writing out a working URL is what
// turns a mention into an instruction, so that is what this looks for.
func instruction(line string) bool {
	if strings.Contains(line, "…") || strings.Contains(line, "...") {
		return false
	}
	return strings.Contains(line, "://") || strings.Contains(line, "$")
}

// ADR-0014: nothing this project tells somebody to run arrives unread.
//
// The rule is easy to state and easy to lose: the convenient install line is
// one command, the honest one is four, and the convenient one gets pasted into
// a README by whoever is in a hurry. It was, which is why this test exists.
//
// The CI workflow is the one exception, named here rather than pattern-matched
// away: it installs a linter at a pinned version onto an ephemeral runner that
// holds nothing, and it is not something this project asks a user to run.
func TestNothingTellsAnybodyToPipeAURLIntoAShell(t *testing.T) {
	const allowed = ".github/workflows/ci.yml"

	// The normative documents quote the rule and describe the historical
	// design; they are the specification, not instructions to run anything.
	historical := map[string]bool{
		"REQUIREMENTS.md": true,
		"docs/SPEC.md":    true,
	}

	err := filepath.WalkDir(root(), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".md", ".sh", ".yaml", ".yml":
		default:
			return nil
		}
		relative, relErr := filepath.Rel(root(), path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		if relative == allowed || historical[relative] {
			return nil
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // the path comes from walking this repository
		if readErr != nil {
			return readErr
		}
		for number, line := range strings.Split(string(body), "\n") {
			if pipeToShell.MatchString(line) && instruction(line) {
				t.Errorf("%s:%d tells somebody to pipe a download into a shell; publish the script, checksum it, and let them read it first (docs/adr/0014)\n\t%s",
					relative, number+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ADR-0014: the scripts a release tells somebody to run are published with it
// and listed in its checksums, so the verifying step is itself verifiable.
func TestTheInstallScriptsAreReleasedAndChecksummed(t *testing.T) {
	config, err := os.ReadFile(filepath.Join(root(), ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(config)
	checksum, release, found := strings.Cut(text, "\nrelease:")
	if !found {
		t.Fatal(".goreleaser.yaml has no release block")
	}
	for _, script := range []string{"./scripts/install.sh", "./scripts/cloud-shell.sh"} {
		if !strings.Contains(checksum, script) {
			t.Errorf("%s is not in the checksums, so nobody can verify the script they are told to run", script)
		}
		if !strings.Contains(release, script) {
			t.Errorf("%s is not published with the release, so it could only be fetched from a branch", script)
		}
	}
}

// The detector above is only worth having if it fires on the line that started
// this, so here is that line and its neighbours.
func TestThePipeDetectorCatchesTheRealThing(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"curl -fsSL https://raw.githubusercontent.com/o/r/main/scripts/cloud-shell.sh | bash", true},
		{"curl -fsSL https://example.com/i.sh | sudo bash", true},
		{"wget -qO- https://example.com/i.sh | sh", true},
		{"curl -fsSLO $base/install.sh | bash", true},
		// Prose about the pattern, which the records and the scripts both need
		// to be able to write.
		{"The convenient install line is `curl … | sh`, resolving \"latest\" server side.", false},
		{"# Deliberately not documented as `curl ... | bash`.", false},
		// The honest form: fetched as a file, verified, then run.
		{"curl -fsSLO $base/install.sh", false},
		{"grep ' install.sh$' checksums.txt | sha256sum -c -", false},
		{"bash install.sh $V", false},
	}
	for _, test := range cases {
		got := pipeToShell.MatchString(test.line) && instruction(test.line)
		if got != test.want {
			t.Errorf("detector said %v for %q, want %v", got, test.line, test.want)
		}
	}
}
