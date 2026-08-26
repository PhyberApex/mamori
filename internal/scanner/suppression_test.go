package scanner_test

import (
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestSuppressionMatchesHeaderOnlySuppressesAcrossEveryHost(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy"}

	a := scanner.Finding{URL: "https://a.example", Header: "Content-Security-Policy"}
	b := scanner.Finding{URL: "https://b.example", Header: "Content-Security-Policy"}
	other := scanner.Finding{URL: "https://a.example", Header: "X-Frame-Options"}

	if !s.Matches(a) {
		t.Error("Matches(a) = false, want true: header-only suppression should match any host")
	}
	if !s.Matches(b) {
		t.Error("Matches(b) = false, want true: header-only suppression should match any host")
	}
	if s.Matches(other) {
		t.Error("Matches(other) = true, want false: different header should not match")
	}
}

func TestSuppressionMatchesHostOnlySuppressesEveryHeaderForThatHost(t *testing.T) {
	s := scanner.Suppression{Host: "https://legacy.example.com"}

	csp := scanner.Finding{URL: "https://legacy.example.com", Header: "Content-Security-Policy"}
	xfo := scanner.Finding{URL: "https://legacy.example.com", Header: "X-Frame-Options"}
	otherHost := scanner.Finding{URL: "https://other.example.com", Header: "Content-Security-Policy"}

	if !s.Matches(csp) {
		t.Error("Matches(csp) = false, want true: host-only suppression should match any header")
	}
	if !s.Matches(xfo) {
		t.Error("Matches(xfo) = false, want true: host-only suppression should match any header")
	}
	if s.Matches(otherHost) {
		t.Error("Matches(otherHost) = true, want false: different host should not match")
	}
}

func TestSuppressionMatchesBothSuppressesOnlyThatSpecificPair(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy", Host: "https://cdn.example.com"}

	exact := scanner.Finding{URL: "https://cdn.example.com", Header: "Content-Security-Policy"}
	wrongHost := scanner.Finding{URL: "https://other.example.com", Header: "Content-Security-Policy"}
	wrongHeader := scanner.Finding{URL: "https://cdn.example.com", Header: "X-Frame-Options"}

	if !s.Matches(exact) {
		t.Error("Matches(exact) = false, want true: exact header+host pair should match")
	}
	if s.Matches(wrongHost) {
		t.Error("Matches(wrongHost) = true, want false: same header but different host should not match")
	}
	if s.Matches(wrongHeader) {
		t.Error("Matches(wrongHeader) = true, want false: same host but different header should not match")
	}
}

func TestSuppressionMatchesIsCaseInsensitiveExactMatchOnly(t *testing.T) {
	s := scanner.Suppression{Header: "content-security-policy", Host: "HTTPS://CDN.EXAMPLE.COM"}
	f := scanner.Finding{URL: "https://cdn.example.com", Header: "Content-Security-Policy"}

	if !s.Matches(f) {
		t.Error("Matches(f) = false, want true: matching must be case-insensitive")
	}

	glob := scanner.Suppression{Host: "https://*.example.com"}
	sub := scanner.Finding{URL: "https://cdn.example.com", Header: "Content-Security-Policy"}
	if glob.Matches(sub) {
		t.Error("Matches(sub) = true, want false: no glob/wildcard support, exact string match only")
	}
}

func TestApplySuppressionsMarksMatchingFindingsInPlace(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
		{URL: "https://b.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy"}}

	scanner.ApplySuppressions(findings, suppressions)

	if !findings[0].Suppressed {
		t.Error("findings[0].Suppressed = false, want true")
	}
	if findings[1].Suppressed {
		t.Error("findings[1].Suppressed = true, want false: no suppression matches this finding")
	}
}

func TestApplySuppressionsWithNoSuppressionsLeavesFindingsUnsuppressed(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}

	scanner.ApplySuppressions(findings, nil)

	if findings[0].Suppressed {
		t.Error("findings[0].Suppressed = true, want false: no suppressions configured")
	}
}
