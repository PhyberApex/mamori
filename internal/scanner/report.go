package scanner

import (
	"fmt"
	"io"
	"strings"
)

type Reporter interface {
	Report(findings []Finding, w io.Writer) error
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
		if _, err := fmt.Fprintf(w, "%s\n", url); err != nil {
			return err
		}
		for _, f := range byURL[url] {
			var line string
			if f.Status == StatusError {
				line = fmt.Sprintf("  [ERROR] %s", f.Message)
			} else {
				line = fmt.Sprintf("  [%s] %s (%s)", strings.ToUpper(string(f.Status)), f.Header, f.Severity)
				if f.Status != StatusPass && f.Reference != "" {
					line += " → " + f.Reference
				}
			}
			if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}
