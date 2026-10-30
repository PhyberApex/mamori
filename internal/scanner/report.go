package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Reporter interface {
	Report(findings []Finding, w io.Writer) error
}

// JSONReporter emits newline-delimited JSON, one finding per line.
// json.Encoder (rather than json.Marshal + manual writes) streams straight
// to the writer and appends the newline itself, which is exactly the NDJSON
// framing — each Encode call produces one complete line.
type JSONReporter struct{}

func (JSONReporter) Report(findings []Finding, w io.Writer) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiDim    = "\x1b[2m"
)

func colorize(enabled bool, color, s string) string {
	if !enabled {
		return s
	}
	return color + s + ansiReset
}

// statusTag picks the color from severity for missing/weak/exposed/insecure
// findings so a high-severity finding reads as urgent (red) while lower
// severities stay a warning yellow.
func statusTag(f Finding, color bool) string {
	switch f.Status {
	case StatusPass:
		return colorize(color, ansiGreen, "PASS")
	case StatusError:
		return colorize(color, ansiRed, "ERROR")
	}
	c := ansiYellow
	if f.Severity == SeverityHigh {
		c = ansiRed
	}
	switch f.Status {
	case StatusWeak:
		return colorize(color, c, "WEAK")
	case StatusExposed:
		return colorize(color, c, "EXPOSED")
	case StatusInsecure:
		return colorize(color, c, "INSECURE")
	}
	return colorize(color, c, "MISSING")
}

// targetGrade derives a target's letter grade from the highest Severity among
// its gating Findings (Fails at the lowest threshold, i.e. not pass, not
// Suppressed, not Known): none → A, low → B, medium → C, high → D. ok is
// false when any Finding is a StatusError, since nothing was judged — and
// when an error is Suppressed or Known it is still an error, so the check
// looks at Status directly.
func targetGrade(fs []Finding) (grade string, ok bool) {
	grade = "A"
	for _, f := range fs {
		if f.Status == StatusError {
			return "", false
		}
		if !f.Fails(SeverityLow) {
			continue
		}
		switch f.Severity {
		case SeverityHigh:
			grade = "D"
		case SeverityMedium:
			if grade != "D" {
				grade = "C"
			}
		default:
			if grade == "A" {
				grade = "B"
			}
		}
	}
	return grade, true
}

func gradeColor(grade string) string {
	switch grade {
	case "A":
		return ansiGreen
	case "D":
		return ansiRed
	}
	return ansiYellow
}

// distinctFinalURLs returns the non-empty FinalURL values among fs, each
// once, in first-encountered order. Ordinarily at most one: the plain scan
// response and the CORS-probe response usually land on the same redirect
// target, but they're judged independently (see setFinalURL in scan.go) and
// can in principle differ.
func distinctFinalURLs(fs []Finding) []string {
	var finals []string
	seen := map[string]bool{}
	for _, f := range fs {
		if f.FinalURL == "" || seen[f.FinalURL] {
			continue
		}
		seen[f.FinalURL] = true
		finals = append(finals, f.FinalURL)
	}
	return finals
}

// distinctStatusCodes returns the non-zero StatusCode values among fs, each
// once, in first-encountered order. Same rationale as distinctFinalURLs: the
// plain scan response and the CORS-probe response are judged independently
// (see setStatusCode in scan.go) and can in principle land on different
// status codes.
func distinctStatusCodes(fs []Finding) []int {
	var codes []int
	seen := map[int]bool{}
	for _, f := range fs {
		if f.StatusCode == 0 || seen[f.StatusCode] {
			continue
		}
		seen[f.StatusCode] = true
		codes = append(codes, f.StatusCode)
	}
	return codes
}

// TerminalReporter renders findings as human-readable text. Color is opt-in
// rather than inferred from the writer, since the decision of whether the
// destination is an interactive terminal (and whether NO_COLOR is set)
// belongs to the CLI entry point, not this package — see stdinIfPiped in
// cmd/mamori/main.go for the equivalent precedent on the input side.
type TerminalReporter struct {
	Color bool
	// FailOn is the configured -fail-on threshold, needed to render the
	// summary line's verdict clause. It is threaded in outside Report's own
	// signature the same way SarifReporter.BaselineSupplied is — see that
	// field's doc comment for the rationale.
	FailOn Severity
}

func (t TerminalReporter) Report(findings []Finding, w io.Writer) error {
	var urls []string
	byURL := map[string][]Finding{}
	for _, f := range findings {
		if _, seen := byURL[f.URL]; !seen {
			urls = append(urls, f.URL)
		}
		byURL[f.URL] = append(byURL[f.URL], f)
	}

	for _, url := range urls {
		header := colorize(t.Color, ansiBold, url)
		if g, ok := targetGrade(byURL[url]); ok {
			header += "  grade " + colorize(t.Color, gradeColor(g), g)
		}
		if _, err := fmt.Fprintf(w, "%s\n", header); err != nil {
			return err
		}
		for _, final := range distinctFinalURLs(byURL[url]) {
			if _, err := fmt.Fprintf(w, "  → redirected to %s\n", final); err != nil {
				return err
			}
		}
		for _, code := range distinctStatusCodes(byURL[url]) {
			if _, err := fmt.Fprintf(w, "  → responded %d\n", code); err != nil {
				return err
			}
		}
		for _, f := range byURL[url] {
			var line string
			if f.Status == StatusError {
				line = fmt.Sprintf("  [%s] %s", statusTag(f, t.Color), f.Message)
			} else {
				line = fmt.Sprintf("  [%s] %s (%s)", statusTag(f, t.Color), f.Header, f.Severity)
				if f.Status != StatusPass && f.Message != "" {
					line += ": " + f.Message
				}
				if f.Status != StatusPass && f.Reference != "" {
					line += " → " + f.Reference
				}
			}
			if f.Known {
				line += " " + colorize(t.Color, ansiDim, "[KNOWN]")
			}
			if f.Suppressed {
				tag := "[SUPPRESSED]"
				if f.SuppressedReason != "" {
					tag += " (" + f.SuppressedReason + ")"
				}
				line += " " + colorize(t.Color, ansiDim, tag)
			}
			if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintf(w, "\n%s\n", summaryLine(findings, len(urls), t.FailOn))
	return err
}

// summaryStatuses lists the Statuses a summary line counts, and the fixed
// order their clauses render in. StatusPass is deliberately excluded — a
// summary exists to draw attention to what needs attention, not to restate a
// clean result the per-target blocks above already show.
var summaryStatuses = []Status{StatusInsecure, StatusMissing, StatusWeak, StatusExposed, StatusError}

// summaryLine renders the one-line scan summary that follows the last
// target's block: a target count, then whichever of the status / known-
// suppressed / fail-on clauses have something to show, joined by " · ".
// Status and known/suppressed counts are independent tallies over the same
// Finding set rather than a partition — a Finding counted under one status
// clause is counted again under known/suppressed if it carries either flag —
// so every clause here can be read on its own without cross-checking the
// others. A clause is omitted entirely once its own count(s) are all zero.
func summaryLine(findings []Finding, targetCount int, failOn Severity) string {
	parts := []string{fmt.Sprintf("%d target%s", targetCount, pluralSuffix(targetCount))}

	statusCounts := map[Status]int{}
	var known, suppressed int
	for _, f := range findings {
		statusCounts[f.Status]++
		if f.Known {
			known++
		}
		if f.Suppressed {
			suppressed++
		}
	}

	var statusClauses []string
	for _, s := range summaryStatuses {
		if c := statusCounts[s]; c > 0 {
			statusClauses = append(statusClauses, fmt.Sprintf("%d %s", c, s))
		}
	}
	if len(statusClauses) > 0 {
		parts = append(parts, strings.Join(statusClauses, ", "))
	}

	var knownSuppressed []string
	if known > 0 {
		knownSuppressed = append(knownSuppressed, fmt.Sprintf("%d known", known))
	}
	if suppressed > 0 {
		knownSuppressed = append(knownSuppressed, fmt.Sprintf("%d suppressed", suppressed))
	}
	if len(knownSuppressed) > 0 {
		parts = append(parts, strings.Join(knownSuppressed, ", "))
	}

	if failOn != "" {
		verdict := "passed"
		if AnyFails(findings, failOn) {
			verdict = "failed"
		}
		parts = append(parts, fmt.Sprintf("fail-on %s: %s", failOn, verdict))
	}

	return strings.Join(parts, " · ")
}

// pluralSuffix returns "s" unless n is exactly 1, so callers can render an
// English count ("1 target" / "2 targets") without a branch of their own.
func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
