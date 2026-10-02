package scanner_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

	scanner.ApplySuppressions(findings, suppressions, time.Now(), &bytes.Buffer{})

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

	scanner.ApplySuppressions(findings, nil, time.Now(), &bytes.Buffer{})

	if findings[0].Suppressed {
		t.Error("findings[0].Suppressed = true, want false: no suppressions configured")
	}
}

func TestApplySuppressionsCarriesReasonOntoMatchingFinding(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy", Reason: "accepted risk, tracked in JIRA-123"}}

	scanner.ApplySuppressions(findings, suppressions, time.Now(), &bytes.Buffer{})

	if !findings[0].Suppressed {
		t.Fatal("findings[0].Suppressed = false, want true")
	}
	if findings[0].SuppressedReason != "accepted risk, tracked in JIRA-123" {
		t.Errorf("findings[0].SuppressedReason = %q, want the configured reason", findings[0].SuppressedReason)
	}
}

func TestApplySuppressionsLeavesSuppressedReasonEmptyWhenUnset(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy"}}

	scanner.ApplySuppressions(findings, suppressions, time.Now(), &bytes.Buffer{})

	if !findings[0].Suppressed {
		t.Fatal("findings[0].Suppressed = false, want true")
	}
	if findings[0].SuppressedReason != "" {
		t.Errorf("findings[0].SuppressedReason = %q, want empty: no reason configured", findings[0].SuppressedReason)
	}
}

func TestSuppressionExpiredReportsFalseWhenExpiresUnset(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy"}
	if s.Expired(time.Now()) {
		t.Error("Expired() = true, want false: no expires configured")
	}
}

func TestSuppressionExpiredReportsFalseBeforeTheDay(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy", Expires: "2026-06-15"}
	now := time.Date(2026, 6, 14, 23, 59, 59, 0, time.UTC)
	if s.Expired(now) {
		t.Error("Expired() = true, want false: the day before expires has not yet passed")
	}
}

func TestSuppressionExpiredReportsFalseOnTheDayItself(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy", Expires: "2026-06-15"}
	for _, now := range []time.Time{
		time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 6, 15, 23, 59, 59, 0, time.UTC),
	} {
		if s.Expired(now) {
			t.Errorf("Expired(%v) = true, want false: expires is inclusive of the named UTC day", now)
		}
	}
}

func TestSuppressionExpiredReportsTrueAfterTheDay(t *testing.T) {
	s := scanner.Suppression{Header: "Content-Security-Policy", Expires: "2026-06-15"}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	if !s.Expired(now) {
		t.Error("Expired() = false, want true: the named UTC day has fully elapsed")
	}
}

func TestApplySuppressionsFutureExpirySuppressesNormally(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy", Expires: "2099-01-01"}}

	scanner.ApplySuppressions(findings, suppressions, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &bytes.Buffer{})

	if !findings[0].Suppressed {
		t.Error("findings[0].Suppressed = false, want true: expires is still in the future")
	}
}

func TestApplySuppressionsExpiredSuppressionNoLongerMatches(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy", Expires: "2020-01-01"}}

	scanner.ApplySuppressions(findings, suppressions, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &bytes.Buffer{})

	if findings[0].Suppressed {
		t.Error("findings[0].Suppressed = true, want false: expires has passed")
	}
	if findings[0].SuppressedReason != "" {
		t.Errorf("findings[0].SuppressedReason = %q, want empty: an expired suppression carries no reason", findings[0].SuppressedReason)
	}
}

func TestApplySuppressionsExpiredSuppressionFallsThroughToLaterActiveOne(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{
		{Header: "Content-Security-Policy", Expires: "2020-01-01", Reason: "stale"},
		{Header: "Content-Security-Policy", Reason: "still accepted"},
	}

	scanner.ApplySuppressions(findings, suppressions, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &bytes.Buffer{})

	if !findings[0].Suppressed {
		t.Fatal("findings[0].Suppressed = false, want true: a later, still-active suppression also matches")
	}
	if findings[0].SuppressedReason != "still accepted" {
		t.Errorf("findings[0].SuppressedReason = %q, want the still-active suppression's reason", findings[0].SuppressedReason)
	}
}

func TestApplySuppressionsWritesOneStderrLineForAnExpiredSuppressionThatMatched(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
		{URL: "https://b.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy", Expires: "2020-01-01"}}

	var stderr bytes.Buffer
	scanner.ApplySuppressions(findings, suppressions, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &stderr)

	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stderr has %d lines, want exactly 1 even though the expired suppression matched 2 findings\nstderr:\n%s", len(lines), stderr.String())
	}
	if !strings.Contains(lines[0], "Content-Security-Policy") {
		t.Errorf("stderr line %q does not name the expired suppression", lines[0])
	}
}

func TestApplySuppressionsWritesNoStderrForExpiredSuppressionMatchingNothing(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	suppressions := []scanner.Suppression{{Header: "Content-Security-Policy", Expires: "2020-01-01"}}

	var stderr bytes.Buffer
	scanner.ApplySuppressions(findings, suppressions, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &stderr)

	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty: the expired suppression matched no finding this run", stderr.String())
	}
}
