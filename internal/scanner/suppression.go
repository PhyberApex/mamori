package scanner

import "strings"

// Suppression marks Findings matching Header and/or Host as an accepted
// risk or known false positive, per the "suppressions" list in the
// .mamori.yaml config-file layer. An empty field matches any value for
// that field, so a Suppression with only Host set suppresses every header
// for that host, and one with only Header set suppresses that header
// across every scanned host.
type Suppression struct {
	Header string `yaml:"header"`
	Host   string `yaml:"host"`
}

// Matches reports whether s suppresses f. Comparison is case-insensitive
// exact string matching — no glob/wildcard support — against f.Header and
// the literal target string mamori scanned (f.URL), not a re-parsed
// hostname.
func (s Suppression) Matches(f Finding) bool {
	if s.Header != "" && !strings.EqualFold(s.Header, f.Header) {
		return false
	}
	if s.Host != "" && !strings.EqualFold(s.Host, f.URL) {
		return false
	}
	return true
}

// ApplySuppressions marks each Finding in findings whose Suppressed field
// should be set, given suppressions. It mutates findings in place, the
// same in-place-by-index pattern Scan already uses to stamp each Finding's
// URL, rather than returning a new slice.
func ApplySuppressions(findings []Finding, suppressions []Suppression) {
	for i := range findings {
		for _, s := range suppressions {
			if s.Matches(findings[i]) {
				findings[i].Suppressed = true
				break
			}
		}
	}
}
