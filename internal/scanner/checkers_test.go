package scanner_test

import (
	"net/http"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestCheckersIdentity(t *testing.T) {
	tests := []struct {
		checker      scanner.Checker
		wantHeader   string
		wantSeverity scanner.Severity
	}{
		{scanner.HSTSChecker{}, "Strict-Transport-Security", scanner.SeverityHigh},
		{scanner.ContentTypeOptionsChecker{}, "X-Content-Type-Options", scanner.SeverityMedium},
		{scanner.FrameOptionsChecker{}, "X-Frame-Options", scanner.SeverityMedium},
		{scanner.CSPChecker{}, "Content-Security-Policy", scanner.SeverityHigh},
		{scanner.ReferrerPolicyChecker{}, "Referrer-Policy", scanner.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.wantHeader, func(t *testing.T) {
			missing := tt.checker.Check(http.Header{})
			if len(missing) != 1 {
				t.Fatalf("Check() on empty headers returned %d findings, want 1", len(missing))
			}
			if missing[0].Header != tt.wantHeader {
				t.Errorf("Header = %q, want %q", missing[0].Header, tt.wantHeader)
			}
			if missing[0].Status != scanner.StatusMissing {
				t.Errorf("Status = %q, want %q", missing[0].Status, scanner.StatusMissing)
			}
			if missing[0].Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", missing[0].Severity, tt.wantSeverity)
			}
			if missing[0].Reference == "" {
				t.Error("Reference is empty, want a docs URL")
			}

			present := tt.checker.Check(http.Header{tt.wantHeader: {"some-value"}})
			if present[0].Status != scanner.StatusPass {
				t.Errorf("Status with header set = %q, want %q", present[0].Status, scanner.StatusPass)
			}

			empty := tt.checker.Check(http.Header{tt.wantHeader: {""}})
			if empty[0].Status != scanner.StatusMissing {
				t.Errorf("Status with empty header value = %q, want %q", empty[0].Status, scanner.StatusMissing)
			}
		})
	}
}
