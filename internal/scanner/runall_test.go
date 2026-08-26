package scanner_test

import (
	"net/http"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestRunAllFansOutAcrossDefaultCheckers(t *testing.T) {
	findings := scanner.RunAll(scanner.DefaultCheckers(), http.Header{
		"Content-Security-Policy": {"default-src 'self'"},
	})

	statusByHeader := map[string]scanner.Status{}
	for _, f := range findings {
		statusByHeader[f.Header] = f.Status
	}

	// No Set-Cookie header is present, so CookieChecker contributes no
	// findings here (unlike the other checkers, an absent cookie jar isn't
	// itself a finding) and the expected count/map below is unaffected by
	// its inclusion in DefaultCheckers().
	want := map[string]scanner.Status{
		"Strict-Transport-Security":    scanner.StatusMissing,
		"X-Content-Type-Options":       scanner.StatusMissing,
		"X-Frame-Options":              scanner.StatusMissing,
		"Content-Security-Policy":      scanner.StatusPass,
		"Referrer-Policy":              scanner.StatusMissing,
		"Cross-Origin-Opener-Policy":   scanner.StatusMissing,
		"Cross-Origin-Embedder-Policy": scanner.StatusMissing,
		"Cross-Origin-Resource-Policy": scanner.StatusMissing,
		"Permissions-Policy":           scanner.StatusMissing,
	}
	if len(findings) != len(want) {
		t.Fatalf("RunAll() returned %d findings, want %d", len(findings), len(want))
	}
	for header, wantStatus := range want {
		if statusByHeader[header] != wantStatus {
			t.Errorf("%s status = %q, want %q", header, statusByHeader[header], wantStatus)
		}
	}
}
