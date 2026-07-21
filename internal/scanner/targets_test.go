package scanner_test

import (
	"io"
	"strings"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func assertTargets(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ResolveTargets() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ResolveTargets()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestResolveTargetsArgsOnly(t *testing.T) {
	got, err := scanner.ResolveTargets([]string{"https://example.com", "http://other.org"}, nil)
	if err != nil {
		t.Fatalf("ResolveTargets() returned error: %v", err)
	}
	assertTargets(t, got, "https://example.com", "http://other.org")
}

func TestResolveTargetsStdinOnly(t *testing.T) {
	stdin := strings.NewReader("https://example.com\n\nhttp://other.org\n")
	got, err := scanner.ResolveTargets(nil, stdin)
	if err != nil {
		t.Fatalf("ResolveTargets() returned error: %v", err)
	}
	assertTargets(t, got, "https://example.com", "http://other.org")
}

func TestResolveTargetsMixedArgsAndStdin(t *testing.T) {
	stdin := strings.NewReader("https://piped.example\n")
	got, err := scanner.ResolveTargets([]string{"https://arg.example"}, stdin)
	if err != nil {
		t.Fatalf("ResolveTargets() returned error: %v", err)
	}
	assertTargets(t, got, "https://arg.example", "https://piped.example")
}

func TestResolveTargetsDeduplicates(t *testing.T) {
	stdin := strings.NewReader("https://example.com\nhttps://other.org\n")
	got, err := scanner.ResolveTargets([]string{"https://example.com"}, stdin)
	if err != nil {
		t.Fatalf("ResolveTargets() returned error: %v", err)
	}
	assertTargets(t, got, "https://example.com", "https://other.org")
}

func TestResolveTargetsRejectsInvalidURL(t *testing.T) {
	invalid := []string{"not-a-url", "ftp://files.example", "https://", "://missing-scheme"}
	for _, url := range invalid {
		t.Run(url, func(t *testing.T) {
			_, err := scanner.ResolveTargets([]string{url}, nil)
			if err == nil {
				t.Fatalf("ResolveTargets(%q) returned nil error, want invalid URL error", url)
			}
			if !strings.Contains(err.Error(), url) {
				t.Errorf("error %q does not mention the offending URL %q", err, url)
			}
		})
	}
}

func TestResolveTargetsErrorsOnEmptyInput(t *testing.T) {
	cases := map[string]struct {
		args  []string
		stdin io.Reader
	}{
		"no args, no stdin":         {args: nil, stdin: nil},
		"no args, blank-only stdin": {args: nil, stdin: strings.NewReader("\n  \n")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := scanner.ResolveTargets(tc.args, tc.stdin)
			if err == nil {
				t.Fatal("ResolveTargets() returned nil error, want no-targets error")
			}
		})
	}
}
