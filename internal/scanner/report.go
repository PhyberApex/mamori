package scanner

import (
	"encoding/json"
	"fmt"
	"io"
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

// TerminalReporter renders findings as human-readable text. Color is opt-in
// rather than inferred from the writer, since the decision of whether the
// destination is an interactive terminal (and whether NO_COLOR is set)
// belongs to the CLI entry point, not this package — see stdinIfPiped in
// cmd/mamori/main.go for the equivalent precedent on the input side.
type TerminalReporter struct {
	Color bool
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
		if _, err := fmt.Fprintf(w, "%s\n", colorize(t.Color, ansiBold, url)); err != nil {
			return err
		}
		for _, final := range distinctFinalURLs(byURL[url]) {
			if _, err := fmt.Fprintf(w, "  → redirected to %s\n", final); err != nil {
				return err
			}
		}
		for _, f := range byURL[url] {
			var line string
			if f.Status == StatusError {
				line = fmt.Sprintf("  [%s] %s", statusTag(f, t.Color), f.Message)
			} else {
				line = fmt.Sprintf("  [%s] %s (%s)", statusTag(f, t.Color), f.Header, f.Severity)
				if (f.Status == StatusWeak || f.Status == StatusExposed || f.Status == StatusInsecure) && f.Message != "" {
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
	return nil
}
