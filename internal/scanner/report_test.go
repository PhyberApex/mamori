package scanner_test

import (
	"bytes"
	"encoding/json"
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

func TestTerminalReporterShowsWeakMessage(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:       "https://a.example",
			Header:    "Strict-Transport-Security",
			Status:    scanner.StatusWeak,
			Severity:  scanner.SeverityHigh,
			Message:   "max-age=0 disables HSTS",
			Reference: "https://owasp.example/hsts",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.TerminalReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"WEAK", "Strict-Transport-Security", "max-age=0 disables HSTS", "https://owasp.example/hsts"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, out)
		}
	}

	//nolint:gosec // G101 false positive: ANSI color assertion, not credentials
	if !strings.Contains(out, "\x1b[31mWEAK\x1b[0m") {
		t.Errorf("WEAK tag for high-severity finding is not red\noutput:\n%q", out)
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

func TestTerminalReporterColorsOutput(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:      "https://a.example",
			Header:   "Strict-Transport-Security",
			Status:   scanner.StatusPass,
			Severity: scanner.SeverityHigh,
		},
		{
			URL:      "https://a.example",
			Header:   "X-Frame-Options",
			Status:   scanner.StatusMissing,
			Severity: scanner.SeverityMedium,
		},
		{
			URL:      "https://a.example",
			Header:   "Content-Security-Policy",
			Status:   scanner.StatusMissing,
			Severity: scanner.SeverityHigh,
		},
		{
			URL:     "https://down.example",
			Status:  scanner.StatusError,
			Message: "connection refused",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.TerminalReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}
	out := buf.String()

	//nolint:gosec // G101 false positive: ANSI color assertions, not credentials
	for desc, want := range map[string]string{
		"bold URL":                "\x1b[1mhttps://a.example\x1b[0m",
		"green PASS":              "\x1b[32mPASS\x1b[0m",
		"yellow MISSING (medium)": "\x1b[33mMISSING\x1b[0m",
		"red MISSING (high)":      "\x1b[31mMISSING\x1b[0m",
		"red ERROR":               "\x1b[31mERROR\x1b[0m",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s (%q)\noutput:\n%q", desc, want, out)
		}
	}

	yellowIdx := strings.Index(out, "\x1b[33mMISSING")
	xfoIdx := strings.Index(out, "X-Frame-Options")
	if yellowIdx == -1 || xfoIdx == -1 || xfoIdx < yellowIdx {
		t.Errorf("yellow MISSING does not precede its medium-severity header\noutput:\n%q", out)
	}
}

func TestTerminalReporterMarksSuppressedFindings(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:        "https://a.example",
			Header:     "Content-Security-Policy",
			Status:     scanner.StatusMissing,
			Severity:   scanner.SeverityHigh,
			Suppressed: true,
		},
		{
			URL:      "https://a.example",
			Header:   "X-Frame-Options",
			Status:   scanner.StatusMissing,
			Severity: scanner.SeverityMedium,
		},
	}

	var buf bytes.Buffer
	if err := (scanner.TerminalReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var suppressedLine, xfoLine string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "Content-Security-Policy") {
			suppressedLine = line
		}
		if strings.Contains(line, "X-Frame-Options") {
			xfoLine = line
		}
	}
	if !strings.Contains(suppressedLine, "SUPPRESSED") {
		t.Errorf("suppressed finding's line does not mention SUPPRESSED\nline: %q", suppressedLine)
	}
	if strings.Contains(xfoLine, "SUPPRESSED") {
		t.Errorf("non-suppressed finding's line mentions SUPPRESSED\nline: %q", xfoLine)
	}
}

func TestJSONReporterEmitsOneFindingPerLine(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:       "https://a.example",
			Header:    "X-Frame-Options",
			Status:    scanner.StatusMissing,
			Severity:  scanner.SeverityMedium,
			Reference: "https://owasp.example/xfo",
		},
		{
			URL:     "https://down.example",
			Status:  scanner.StatusError,
			Message: "context deadline exceeded",
		},
		{
			URL:       "https://a.example",
			Header:    "Referrer-Policy",
			Status:    scanner.StatusWeak,
			Severity:  scanner.SeverityLow,
			Message:   "unsafe-url leaks the full URL, including query strings, to third parties on cross-origin requests",
			Reference: "https://owasp.example/referrer-policy",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.JSONReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want one per finding (3)\noutput:\n%s", len(lines), buf.String())
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\nline: %s", err, lines[0])
	}
	for key, want := range map[string]string{
		"url":       "https://a.example",
		"header":    "X-Frame-Options",
		"status":    "missing",
		"severity":  "medium",
		"reference": "https://owasp.example/xfo",
	} {
		if got := first[key]; got != want {
			t.Errorf("first finding %q = %v, want %q", key, got, want)
		}
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v\nline: %s", err, lines[1])
	}
	if second["status"] != "error" {
		t.Errorf("error finding status = %v, want %q", second["status"], "error")
	}
	if second["message"] != "context deadline exceeded" {
		t.Errorf("error finding message = %v, want the scan error", second["message"])
	}

	var third map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &third); err != nil {
		t.Fatalf("line 3 is not valid JSON: %v\nline: %s", err, lines[2])
	}
	if third["status"] != "weak" {
		t.Errorf("weak finding status = %v, want %q", third["status"], "weak")
	}
	if third["message"] != "unsafe-url leaks the full URL, including query strings, to third parties on cross-origin requests" {
		t.Errorf("weak finding message = %v, want the weakness explanation", third["message"])
	}
}

func TestJSONReporterMarksSuppressedFindingWithoutChangingStatus(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:        "https://a.example",
			Header:     "Content-Security-Policy",
			Status:     scanner.StatusMissing,
			Severity:   scanner.SeverityHigh,
			Suppressed: true,
		},
		{
			URL:      "https://a.example",
			Header:   "X-Frame-Options",
			Status:   scanner.StatusMissing,
			Severity: scanner.SeverityMedium,
		},
	}

	var buf bytes.Buffer
	if err := (scanner.JSONReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per finding (2)\noutput:\n%s", len(lines), buf.String())
	}

	var suppressed map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &suppressed); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\nline: %s", err, lines[0])
	}
	if suppressed["status"] != "missing" {
		t.Errorf("suppressed finding status = %v, want %q unchanged", suppressed["status"], "missing")
	}
	if suppressed["suppressed"] != true {
		t.Errorf("suppressed finding suppressed = %v, want true", suppressed["suppressed"])
	}

	var unsuppressed map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &unsuppressed); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v\nline: %s", err, lines[1])
	}
	if _, present := unsuppressed["suppressed"]; present {
		t.Errorf("unsuppressed finding has a %q key, want it omitted", "suppressed")
	}
}
