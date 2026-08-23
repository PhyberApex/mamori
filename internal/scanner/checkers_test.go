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
		validValue   string
	}{
		{scanner.HSTSChecker{}, "Strict-Transport-Security", scanner.SeverityHigh, "max-age=63072000; includeSubDomains"},
		{scanner.ContentTypeOptionsChecker{}, "X-Content-Type-Options", scanner.SeverityMedium, "nosniff"},
		{scanner.FrameOptionsChecker{}, "X-Frame-Options", scanner.SeverityMedium, "DENY"},
		{scanner.CSPChecker{}, "Content-Security-Policy", scanner.SeverityHigh, "default-src 'self'"},
		{scanner.ReferrerPolicyChecker{}, "Referrer-Policy", scanner.SeverityLow, "strict-origin-when-cross-origin"},
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

			present := tt.checker.Check(http.Header{tt.wantHeader: {tt.validValue}})
			if present[0].Status != scanner.StatusPass {
				t.Errorf("Status with valid value %q = %q, want %q", tt.validValue, present[0].Status, scanner.StatusPass)
			}

			empty := tt.checker.Check(http.Header{tt.wantHeader: {""}})
			if empty[0].Status != scanner.StatusMissing {
				t.Errorf("Status with empty header value = %q, want %q", empty[0].Status, scanner.StatusMissing)
			}
		})
	}
}

func TestHSTSWeakValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"zero max-age", "max-age=0"},
		{"negative max-age", "max-age=-1"},
		{"unparseable max-age", "max-age=notanumber"},
		{"missing max-age directive", "includeSubDomains"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.HSTSChecker{}.Check(http.Header{"Strict-Transport-Security": {tt.value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestHSTSAcceptsValidMaxAge(t *testing.T) {
	tests := []string{
		"max-age=63072000",
		"max-age=63072000; includeSubDomains",
		"includeSubDomains; max-age=63072000",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.HSTSChecker{}.Check(http.Header{"Strict-Transport-Security": {value}})
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestHSTSFlagsWeakAmongDuplicateHeaders(t *testing.T) {
	// A misconfigured proxy/CDN can append a second Strict-Transport-Security
	// header instead of overwriting the origin's. headers.Get would only see
	// whichever value happens to be first, so the reported status must not
	// depend on that order.
	headers := http.Header{"Strict-Transport-Security": {"max-age=63072000", "max-age=0"}}
	findings := scanner.HSTSChecker{}.Check(headers)
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want an explanation")
	}

	reversed := http.Header{"Strict-Transport-Security": {"max-age=0", "max-age=63072000"}}
	findings = scanner.HSTSChecker{}.Check(reversed)
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q (order should not matter)", findings[0].Status, scanner.StatusWeak)
	}
}

func TestCheckValueIgnoresBlankDuplicateOccurrence(t *testing.T) {
	// Some infra appends a stray empty duplicate header instead of leaving
	// the original alone. That blank occurrence carries no value to judge
	// and must not itself be treated as a weak one.
	tests := []struct {
		name    string
		checker scanner.Checker
		headers http.Header
	}{
		{"HSTS", scanner.HSTSChecker{}, http.Header{"Strict-Transport-Security": {"max-age=63072000", ""}}},
		{"ContentTypeOptions", scanner.ContentTypeOptionsChecker{}, http.Header{"X-Content-Type-Options": {"nosniff", ""}}},
		{"FrameOptions", scanner.FrameOptionsChecker{}, http.Header{"X-Frame-Options": {"DENY", ""}}},
		{"ReferrerPolicy", scanner.ReferrerPolicyChecker{}, http.Header{"Referrer-Policy": {"strict-origin-when-cross-origin", ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := tt.checker.Check(tt.headers)
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q (blank duplicate should not downgrade a strong value)", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestContentTypeOptionsWeakValues(t *testing.T) {
	tests := []string{"garbage", "sniff"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.ContentTypeOptionsChecker{}.Check(http.Header{"X-Content-Type-Options": {value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestContentTypeOptionsAcceptsCaseInsensitiveValidValue(t *testing.T) {
	tests := []string{"nosniff", "NOSNIFF", "NoSniff"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.ContentTypeOptionsChecker{}.Check(http.Header{"X-Content-Type-Options": {value}})
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestFrameOptionsWeakValues(t *testing.T) {
	tests := []string{"ALLOW-FROM https://example.com", "allowall", "garbage"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.FrameOptionsChecker{}.Check(http.Header{"X-Frame-Options": {value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestFrameOptionsAcceptsCaseInsensitiveValidValues(t *testing.T) {
	tests := []string{"deny", "DENY", "sameorigin", "SAMEORIGIN"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.FrameOptionsChecker{}.Check(http.Header{"X-Frame-Options": {value}})
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestReferrerPolicyWeakValues(t *testing.T) {
	tests := []string{"unsafe-url", "UNSAFE-URL", "Unsafe-Url"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.ReferrerPolicyChecker{}.Check(http.Header{"Referrer-Policy": {value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestReferrerPolicyWeakFallbackList(t *testing.T) {
	// A single value can be a comma-separated fallback list; per spec the
	// browser applies the last *recognized* token, not the value verbatim.
	tests := []string{
		"strict-origin-when-cross-origin, unsafe-url",
		"strict-origin-when-cross-origin, not-a-real-policy, unsafe-url",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.ReferrerPolicyChecker{}.Check(http.Header{"Referrer-Policy": {value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestReferrerPolicyAcceptsFallbackListEndingStrong(t *testing.T) {
	// The reverse order: an unsafe-url earlier in the list is overridden by
	// a later recognized, safe token — that's the effective policy applied.
	findings := scanner.ReferrerPolicyChecker{}.Check(http.Header{
		"Referrer-Policy": {"unsafe-url, strict-origin-when-cross-origin"},
	})
	if findings[0].Status != scanner.StatusPass {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
	}
}
