package scanner_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestTerminalReporterGroupsFindingsByURL(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:      "https://a.example",
			Header:   "Strict-Transport-Security",
			Status:   scanner.StatusPass,
			Severity: scanner.SeverityHigh,
		},
		{
			URL:       "https://a.example",
			Header:    "X-Frame-Options",
			Status:    scanner.StatusMissing,
			Severity:  scanner.SeverityMedium,
			Reference: "https://owasp.example/xfo",
		},
		{
			URL:       "https://b.example",
			Header:    "Content-Security-Policy",
			Status:    scanner.StatusMissing,
			Severity:  scanner.SeverityHigh,
			Reference: "https://owasp.example/csp",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.TerminalReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"https://a.example",
		"https://b.example",
		"PASS",
		"Strict-Transport-Security",
		"MISSING",
		"X-Frame-Options",
		"medium",
		"https://owasp.example/xfo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, out)
		}
	}

	aIdx := strings.Index(out, "https://a.example")
	xfoIdx := strings.Index(out, "X-Frame-Options")
	bIdx := strings.Index(out, "https://b.example")
	if aIdx >= xfoIdx || xfoIdx >= bIdx {
		t.Errorf("findings for a.example are not grouped under its heading\noutput:\n%s", out)
	}
}

func TestTerminalReporterShowsErrorMessage(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:     "https://down.example",
			Status:  scanner.StatusError,
			Message: "context deadline exceeded",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.TerminalReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"https://down.example", "ERROR", "context deadline exceeded"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, out)
		}
	}
}
