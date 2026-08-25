package scanner_test

import (
	"net/http"
	"strings"
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
		{scanner.CORPChecker{}, "Cross-Origin-Resource-Policy", scanner.SeverityMedium, "same-origin"},
		{scanner.PermissionsPolicyChecker{}, "Permissions-Policy", scanner.SeverityMedium, "geolocation=()"},
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
		{"CSP", scanner.CSPChecker{}, http.Header{"Content-Security-Policy": {"default-src 'self'", ""}}},
		{"ReferrerPolicy", scanner.ReferrerPolicyChecker{}, http.Header{"Referrer-Policy": {"strict-origin-when-cross-origin", ""}}},
		{"CORP", scanner.CORPChecker{}, http.Header{"Cross-Origin-Resource-Policy": {"same-origin", ""}}},
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

func TestCORPWeakValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"cross-origin opts out", "cross-origin"},
		{"unrecognized value", "garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.CORPChecker{}.Check(http.Header{"Cross-Origin-Resource-Policy": {tt.value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestCSPWeakValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"unsafe-inline in script-src", "default-src 'self'; script-src 'unsafe-inline'; object-src 'none'"},
		{"unsafe-eval in script-src", "default-src 'self'; script-src 'unsafe-eval'; object-src 'none'"},
		{"unsafe-inline case-insensitive", "default-src 'self'; script-src 'UNSAFE-INLINE'; object-src 'none'"},
		{"bare wildcard source", "default-src 'self'; img-src *; object-src 'none'"},
		{"missing object-src and default-src", "script-src 'self'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.CSPChecker{}.Check(http.Header{"Content-Security-Policy": {tt.value}})
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestCORPAcceptsCaseInsensitiveValidValues(t *testing.T) {
	tests := []string{"same-site", "SAME-SITE", "same-origin", "SAME-ORIGIN"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.CORPChecker{}.Check(http.Header{"Cross-Origin-Resource-Policy": {value}})
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestCSPAcceptsStrongValues(t *testing.T) {
	tests := []string{
		"default-src 'self'",
		"object-src 'none'; script-src 'self'",
		"default-src 'self'; img-src https://*.example.com",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			findings := scanner.CSPChecker{}.Check(http.Header{"Content-Security-Policy": {value}})
			if findings[0].Status != scanner.StatusPass {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
			}
		})
	}
}

func TestCookieCheckerNoCookiesProducesNoFindings(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{})
	if len(findings) != 0 {
		t.Errorf("Check() on headers with no Set-Cookie returned %d findings, want 0", len(findings))
	}
}

func TestCookieCheckerFullyLockedDownCookieProducesNoFindings(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {"session_id=abc123; Secure; HttpOnly; SameSite=Strict"},
	})
	if len(findings) != 0 {
		t.Errorf("Check() on a fully-locked-down cookie returned %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestCookieCheckerSameSiteLaxIsAccepted(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {"session_id=abc123; Secure; HttpOnly; SameSite=Lax"},
	})
	if len(findings) != 0 {
		t.Errorf("Check() with SameSite=Lax returned %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestCookieCheckerMissingSecure(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {"session_id=abc123; HttpOnly; SameSite=Strict"},
	})
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Severity != scanner.SeverityHigh {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityHigh)
	}
	if findings[0].Header != "Set-Cookie: session_id (Secure)" {
		t.Errorf("Header = %q, want %q", findings[0].Header, "Set-Cookie: session_id (Secure)")
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want an explanation")
	}
}

func TestCookieCheckerMissingHttpOnly(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {"session_id=abc123; Secure; SameSite=Strict"},
	})
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Severity != scanner.SeverityMedium {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityMedium)
	}
	if findings[0].Header != "Set-Cookie: session_id (HttpOnly)" {
		t.Errorf("Header = %q, want %q", findings[0].Header, "Set-Cookie: session_id (HttpOnly)")
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want an explanation")
	}
}

func TestCookieCheckerWeakSameSite(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"missing SameSite", "session_id=abc123; Secure; HttpOnly"},
		{"SameSite=None", "session_id=abc123; Secure; HttpOnly; SameSite=None"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.CookieChecker{}.Check(http.Header{"Set-Cookie": {tt.value}})
			if len(findings) != 1 {
				t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
			}
			if findings[0].Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
			}
			if findings[0].Severity != scanner.SeverityMedium {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityMedium)
			}
			if findings[0].Header != "Set-Cookie: session_id (SameSite)" {
				t.Errorf("Header = %q, want %q", findings[0].Header, "Set-Cookie: session_id (SameSite)")
			}
			if findings[0].Message == "" {
				t.Error("Message is empty, want an explanation")
			}
		})
	}
}

func TestCookieCheckerCompletelyInsecureCookieProducesThreeFindings(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {"session_id=abc123"},
	})
	if len(findings) != 3 {
		t.Fatalf("Check() returned %d findings, want 3: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != scanner.StatusWeak {
			t.Errorf("Status = %q, want %q", f.Status, scanner.StatusWeak)
		}
	}
}

func TestCookieCheckerEvaluatesMultipleCookiesIndependently(t *testing.T) {
	findings := scanner.CookieChecker{}.Check(http.Header{
		"Set-Cookie": {
			"session_id=abc123; Secure; HttpOnly; SameSite=Strict",
			"tracking_id=xyz789",
		},
	})
	if len(findings) != 3 {
		t.Fatalf("Check() returned %d findings, want 3 (only from tracking_id): %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Header, "tracking_id") {
			t.Errorf("Header = %q, want it to reference tracking_id only", f.Header)
		}
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

func TestBannerDisclosureNoHeadersProducesNoFindings(t *testing.T) {
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{})
	if len(findings) != 0 {
		t.Errorf("Check() on headers with no Server/X-Powered-By returned %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestBannerDisclosureFlagsServerHeader(t *testing.T) {
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{"Server": {"nginx/1.18.0"}})
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Header != "Server" {
		t.Errorf("Header = %q, want %q", findings[0].Header, "Server")
	}
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Severity != scanner.SeverityLow {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityLow)
	}
	if findings[0].Reference == "" {
		t.Error("Reference is empty, want a docs URL")
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want an explanation")
	}
}

func TestBannerDisclosureFlagsXPoweredByHeader(t *testing.T) {
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{"X-Powered-By": {"PHP/8.2.0"}})
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Header != "X-Powered-By" {
		t.Errorf("Header = %q, want %q", findings[0].Header, "X-Powered-By")
	}
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Severity != scanner.SeverityLow {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityLow)
	}
}

func TestBannerDisclosureFlagsBothHeaders(t *testing.T) {
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{
		"Server":       {"nginx/1.18.0"},
		"X-Powered-By": {"PHP/8.2.0"},
	})
	if len(findings) != 2 {
		t.Fatalf("Check() returned %d findings, want 2: %+v", len(findings), findings)
	}
}

func TestBannerDisclosureIgnoresBlankHeaderValue(t *testing.T) {
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{
		"Server":       {""},
		"X-Powered-By": {""},
	})
	if len(findings) != 0 {
		t.Errorf("Check() with blank header values returned %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestBannerDisclosureFlagsValueBehindBlankDuplicateOccurrence(t *testing.T) {
	// Some infra prepends a stray blank duplicate instead of leaving the
	// origin's header alone. headers.Get would only see that blank first
	// occurrence and miss the disclosing one behind it.
	findings := scanner.BannerDisclosureChecker{}.Check(http.Header{
		"Server": {"", "nginx/1.18.0"},
	})
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusWeak)
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want an explanation")
	}
}
