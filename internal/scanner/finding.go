package scanner

import "fmt"

type Status string

const (
	StatusPass    Status = "pass"
	StatusMissing Status = "missing"
	// StatusWeak marks a header that is present but whose value is a known
	// no-op, so it doesn't provide the protection the header exists for.
	// Kept distinct from StatusPass so scans don't silently treat a
	// self-defeating value (e.g. max-age=0) as a clean bill of health.
	StatusWeak  Status = "weak"
	StatusError Status = "error"
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// severityRank gives each severity an ordinal so "at or above" comparisons
// don't rely on string ordering — low < medium < high happens to sort
// correctly as strings today, but that's a coincidence a future rename could
// break silently.
func severityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 0
	case SeverityMedium:
		return 1
	case SeverityHigh:
		return 2
	default:
		return -1
	}
}

// AtLeast reports whether s is at or above threshold in severity.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityRank(s) >= severityRank(threshold)
}

// String and Set satisfy flag.Value directly on Severity — the same
// validate-on-parse pattern config.Output uses for -o — so a flag like
// -fail-on can take a Severity value without a parallel type wrapping this
// one. The zero value stands for "no threshold" and round-trips as "none",
// since Severity has no zero-value constant of its own.
func (s *Severity) String() string {
	if *s == "" {
		return "none"
	}
	return string(*s)
}

func (s *Severity) Set(v string) error {
	if v == "none" {
		*s = ""
		return nil
	}
	switch Severity(v) {
	case SeverityLow, SeverityMedium, SeverityHigh:
		*s = Severity(v)
		return nil
	}
	return fmt.Errorf("%q is not a known severity (low, medium, high, or none)", v)
}

// The json struct tags pin the wire names independently of the Go field
// names, so renaming a field during a refactor can never silently break
// downstream jq pipelines. Without a tag, encoding/json would emit the
// exported (capitalized) field name instead.
type Finding struct {
	URL       string   `json:"url"`
	Header    string   `json:"header"`
	Status    Status   `json:"status"`
	Severity  Severity `json:"severity"`
	Reference string   `json:"reference"`
	Message   string   `json:"message"`
}

// Fails reports whether f should trip a -fail-on gate at the given
// threshold. A StatusError always fails, regardless of threshold, since a
// scan that couldn't complete shouldn't silently report success; a
// Missing/Weak finding fails once its severity reaches threshold; a Pass
// never fails.
func (f Finding) Fails(threshold Severity) bool {
	if f.Status == StatusError {
		return true
	}
	if f.Status != StatusMissing && f.Status != StatusWeak {
		return false
	}
	return f.Severity.AtLeast(threshold)
}

// AnyFails reports whether any finding trips a -fail-on gate at threshold.
func AnyFails(findings []Finding, threshold Severity) bool {
	for _, f := range findings {
		if f.Fails(threshold) {
			return true
		}
	}
	return false
}
