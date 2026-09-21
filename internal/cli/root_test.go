package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

const testTarget = "/subscriptions/01234567-89ab-cdef-0123-456789abcdef/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store"

func TestVersion(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut, "v0.1.0-test")
		if code != 0 || out.String() != "az-can-i-delete v0.1.0-test\n" || errOut.Len() != 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestCommandHelp(t *testing.T) {
	t.Parallel()
	for _, path := range [][]string{
		{}, {"check"}, {"cordon"}, {"uncordon"}, {"status"}, {"history"},
		{"demo"}, {"patterns"}, {"patterns", "list"}, {"mcp"},
	} {
		t.Run(strings.Join(path, "/"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append(append([]string(nil), path...), "--help")
			code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut, "dev")
			if code != 0 || !strings.Contains(out.String(), "Usage:") || errOut.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"unknown-command"}, {"check"}, {"check", "--unknown-flag"},
		{"version", "extra"}, {"cordon"}, {"uncordon"}, {"status"},
	} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut, "dev")
		if code != 2 || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "error: ") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestUnimplementedCommandsFailExplicitly(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"check", testTarget}, {"check", "--ids", testTarget},
		{"cordon", testTarget}, {"uncordon", testTarget},
		{"status", testTarget}, {"history"}, {"demo", "recorded-example"},
		{"patterns", "list"}, {"mcp"},
	} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut, "dev")
		if code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "not implemented") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestTargetValidation(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"check", "cordon", "uncordon", "status"} {
		for _, tc := range []struct {
			name string
			args []string
			code int
		}{
			{"invalid", []string{"/placeholder"}, 2},
			{"portal", []string{"https://portal.azure.com/#resource" + testTarget + "/overview"}, 1},
			{"slot preserved", []string{strings.ReplaceAll(testTarget, "Microsoft.Storage/storageAccounts/store", "Microsoft.Web/sites/app/slots/staging")}, 1},
			{"extension preserved", []string{testTarget + "/providers/Microsoft.Authorization/locks/L"}, 1},
			{"subscription match", []string{testTarget, "--subscription", "01234567-89AB-CDEF-0123-456789ABCDEF"}, 1},
			{"subscription mismatch", []string{testTarget, "--subscription", "fedcba98-7654-3210-fedc-ba9876543210"}, 2},
			{"subscription invalid", []string{testTarget, "--subscription", "not-a-guid"}, 2},
			{"subscription empty", []string{testTarget, "--subscription="}, 2},
			{"URL credentials", []string{"https://secret:password@portal.azure.com/#resource" + testTarget}, 2},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				assertTargetCommand(t, append([]string{command}, tc.args...), tc.code)
			})
		}
	}
}

func TestCheckMultipleTargets(t *testing.T) {
	t.Parallel()
	other := strings.ReplaceAll(testTarget, "01234567-89ab-cdef-0123-456789abcdef", "fedcba98-7654-3210-fedc-ba9876543210")
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"positional", []string{testTarget, other}, 1},
		{"space delimited ids", []string{"--ids", testTarget, other}, 1},
		{"repeated ids", []string{"--ids", testTarget, "--ids", other}, 1},
		{"invalid second positional", []string{testTarget, "/placeholder"}, 2},
		{"invalid second id", []string{"--ids", testTarget, "/placeholder"}, 2},
		{"invalid repeated id", []string{"--ids", testTarget, "--ids", "/placeholder"}, 2},
		{"empty id", []string{"--ids="}, 2},
		{"invalid id with valid positional", []string{"--ids=", testTarget}, 2},
		{"cross subscription mismatch", []string{"--ids", testTarget, other, "--subscription", "01234567-89ab-cdef-0123-456789abcdef"}, 2},
		{"same subscription", []string{"--ids", testTarget, testTarget + "2", "--subscription", "01234567-89AB-CDEF-0123-456789ABCDEF"}, 1},
		{"comma in name is not a list", []string{"--ids", testTarget + ",Another"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTargetCommand(t, append([]string{"check"}, tc.args...), tc.code)
		})
	}
}

func assertTargetCommand(t *testing.T, args []string, wantCode int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut, "dev")
	if code != wantCode || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "error: ") {
		t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
	}
	if (code == 1) != strings.Contains(errOut.String(), "not implemented") {
		t.Fatalf("unexpected runtime/validation error: %s", errOut.String())
	}
	if strings.Contains(errOut.String(), "secret") || strings.Contains(errOut.String(), "password") {
		t.Fatalf("error echoed credentials: %s", errOut.String())
	}
}

func TestIndependentCommandDefaults(t *testing.T) {
	t.Parallel()
	root := NewRootCommand("dev")
	for _, tc := range []struct {
		command, flag, want string
	}{
		{"check", "window", "30d"},
		{"cordon", "window", "7d"},
		{"mcp", "redact-tags", "true"},
		{"check", "data-plane", "false"},
	} {
		command, _, err := root.Find([]string{tc.command})
		if err != nil {
			t.Fatal(err)
		}

		flag := command.Flags().Lookup(tc.flag)
		if flag == nil || flag.DefValue != tc.want {
			t.Errorf("%s --%s: expected default %q", tc.command, tc.flag, tc.want)
		}
	}
}

func TestOutputFormatValidation(t *testing.T) {
	for _, format := range []string{"json", "jsonc", "table", "tsv", "yaml", "none", "invalid"} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"check", testTarget, "-o", format}, strings.NewReader(""), &out, &errOut, "dev")
		want := 1
		if format == "invalid" {
			want = 2
		}
		if code != want || out.Len() != 0 {
			t.Fatalf("%s: %d %s", format, code, errOut.String())
		}
	}
}

func TestUnsupportedQuery(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"check", testTarget, "--query", "verdict"}, strings.NewReader(""), &out, &errOut, "dev")
	if code != 2 || !strings.Contains(errOut.String(), "query is not implemented") {
		t.Fatalf("%d %s", code, errOut.String())
	}
}

func TestDefaultOutputFormat(t *testing.T) {
	if defaultOutputFormat(&bytes.Buffer{}) != "json" {
		t.Fatal("non-TTY default")
	}
	if formatForTerminal(true) != "table" || formatForTerminal(false) != "json" {
		t.Fatal("terminal default")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	if defaultOutputFormat(writer) != "json" {
		t.Fatal("real pipe fd mistaken for a terminal")
	}
}
