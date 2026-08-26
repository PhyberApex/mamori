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

func colorize(color, s string) string {
	return color + s + ansiReset
}

// statusTag picks the color from severity for missing/weak headers so a
// high-severity finding reads as urgent (red) while lower severities stay a
// warning yellow.
func statusTag(f Finding) string {
	switch f.Status {
	case StatusPass:
		return colorize(ansiGreen, "PASS")
	case StatusError:
		return colorize(ansiRed, "ERROR")
	}
	color := ansiYellow
	if f.Severity == SeverityHigh {
		color = ansiRed
	}
	if f.Status == StatusWeak {
		return colorize(color, "WEAK")
	}
	return colorize(color, "MISSING")
}

type TerminalReporter struct{}

func (TerminalReporter) Report(findings []Finding, w io.Writer) error {
	var urls []string
	byURL := map[string][]Finding{}
	for _, f := range findings {
		if _, seen := byURL[f.URL]; !seen {
			urls = append(urls, f.URL)
		}
		byURL[f.URL] = append(byURL[f.URL], f)
	}

	for _, url := range urls {
		if _, err := fmt.Fprintf(w, "%s\n", colorize(ansiBold, url)); err != nil {
			return err
		}
		for _, f := range byURL[url] {
			var line string
			if f.Status == StatusError {
				line = fmt.Sprintf("  [%s] %s", statusTag(f), f.Message)
			} else {
				line = fmt.Sprintf("  [%s] %s (%s)", statusTag(f), f.Header, f.Severity)
				if f.Status == StatusWeak && f.Message != "" {
					line += ": " + f.Message
				}
				if f.Status != StatusPass && f.Reference != "" {
					line += " → " + f.Reference
				}
			}
			if f.Suppressed {
				line += " " + colorize(ansiDim, "[SUPPRESSED]")
			}
			if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}
