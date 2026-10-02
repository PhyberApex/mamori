package scanner

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// expiresLayout is the "expires" field's on-disk layout: a UTC calendar
// day, e.g. "2026-01-31".
const expiresLayout = "2006-01-02"

// Suppression marks Findings matching Header and/or Host as an accepted
// risk or known false positive, per the "suppressions" list in the
// .mamori.yaml config-file layer. An empty field matches any value for
// that field, so a Suppression with only Host set suppresses every header
// for that host, and one with only Header set suppresses that header
// across every scanned host.
type Suppression struct {
	Header string `yaml:"header"`
	Host   string `yaml:"host"`
	// Reason is freeform text explaining why the Suppression exists. It is
	// carried into every output format next to a matching Finding's
	// suppressed marking, but only while the Suppression is actively
	// matching — an expired Suppression renders no reason, since it isn't
	// suppressing anything anymore.
	Reason string `yaml:"reason"`
	// Expires is the last UTC calendar day, in YYYY-MM-DD form, the
	// Suppression still applies. Empty means it never expires. Validated at
	// config-load time (see ParseExpires) rather than left to fail silently
	// at match time.
	Expires string `yaml:"expires"`
}

// ParseExpires parses an "expires" field's YYYY-MM-DD value, returning the
// first UTC instant at which a Suppression carrying that value stops
// matching. expires is inclusive of the named day itself, so that instant
// is the start of the following day, not the start of the named day.
func ParseExpires(v string) (time.Time, error) {
	d, err := time.Parse(expiresLayout, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a valid YYYY-MM-DD date", v)
	}
	return d.AddDate(0, 0, 1), nil
}

// Expired reports whether s's Expires day, if set, has fully elapsed as of
// now (compared in UTC). An unset Expires never expires. now is a parameter
// rather than a direct time.Now() call so callers (and their tests) control
// "now" explicitly instead of it being buried in this matching logic.
// Config-load validation (see ParseExpires) already guarantees a
// config-file Suppression's Expires parses; a Suppression built directly
// with an unparseable Expires (e.g. in a test) is treated as never expired.
func (s Suppression) Expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	cutoff, err := ParseExpires(s.Expires)
	if err != nil {
		return false
	}
	return !now.UTC().Before(cutoff)
}

// Matches reports whether s suppresses f. Comparison is case-insensitive
// exact string matching — no glob/wildcard support — against f.Header and
// the literal target string mamori scanned (f.URL), not a re-parsed
// hostname. Matches does not consider Expired: callers that care about
// expiry check it separately, since a Finding an expired Suppression would
// otherwise have matched is treated differently (not simply "unmatched").
func (s Suppression) Matches(f Finding) bool {
	if s.Header != "" && !strings.EqualFold(s.Header, f.Header) {
		return false
	}
	if s.Host != "" && !strings.EqualFold(s.Host, f.URL) {
		return false
	}
	return true
}

// describe renders s's match criteria for the expired-suppression stderr
// line below, e.g. `header="X-Frame-Options" host="https://a.example"` —
// whichever of header/host s set, mirroring the config-load invariant that
// at least one of them is always set.
func (s Suppression) describe() string {
	var parts []string
	if s.Header != "" {
		parts = append(parts, fmt.Sprintf("header=%q", s.Header))
	}
	if s.Host != "" {
		parts = append(parts, fmt.Sprintf("host=%q", s.Host))
	}
	return strings.Join(parts, " ")
}

// ApplySuppressions marks each Finding in findings whose Suppressed (and
// SuppressedReason) fields should be set, given suppressions as of now. It
// mutates findings in place, the same in-place-by-index pattern Scan
// already uses to stamp each Finding's URL, rather than returning a new
// slice.
//
// A Finding matching an expired Suppression is left unsuppressed — as if
// that Suppression didn't exist — but a later, still-active Suppression in
// the list may still suppress it. For each Suppression that has expired and
// matched at least one Finding this run, ApplySuppressions writes exactly
// one line to stderr naming it, so the reader knows why a previously-quiet
// Finding reappeared; an expired Suppression matching nothing this run
// writes nothing, since there's nothing to re-review.
func ApplySuppressions(findings []Finding, suppressions []Suppression, now time.Time, stderr io.Writer) {
	expiredMatched := make([]bool, len(suppressions))
	for i := range findings {
		for si, s := range suppressions {
			if !s.Matches(findings[i]) {
				continue
			}
			if s.Expired(now) {
				expiredMatched[si] = true
				continue
			}
			findings[i].Suppressed = true
			findings[i].SuppressedReason = s.Reason
			break
		}
	}
	for si, matched := range expiredMatched {
		if matched {
			_, _ = fmt.Fprintf(stderr, "mamori: suppression expired, no longer suppressing matched findings: %s\n", suppressions[si].describe())
		}
	}
}
