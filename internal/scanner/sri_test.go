package scanner_test

import (
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

const sriTargetURL = "https://example.com/"

func TestSRICheckerFlagsCrossOriginWithoutIntegrity(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"script src", `<script src="https://cdn.example.net/app.js"></script>`},
		{"link stylesheet href", `<link rel="stylesheet" href="https://cdn.example.net/app.css">`},
		{"protocol-relative URL", `<script src="//cdn.example.net/app.js"></script>`},
		{"link with multiple rel tokens", `<link rel="preload stylesheet" href="https://cdn.example.net/app.css">`},
		{"blank integrity treated as missing", `<script src="https://cdn.example.net/app.js" integrity=""></script>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.SRIChecker{}.CheckBody([]byte(tt.html), sriTargetURL)
			if len(findings) != 1 {
				t.Fatalf("CheckBody() returned %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", f.Status, scanner.StatusWeak)
			}
			if f.Severity != scanner.SeverityLow {
				t.Errorf("Severity = %q, want %q", f.Severity, scanner.SeverityLow)
			}
			if f.Reference == "" {
				t.Error("Reference is empty, want a docs URL")
			}
			if f.Message == "" {
				t.Error("Message is empty")
			}
		})
	}
}

func TestSRICheckerIgnoresSafeCases(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"same-origin absolute script", `<script src="https://example.com/app.js"></script>`},
		{"same-origin relative script", `<script src="/app.js"></script>`},
		{"cross-origin script with integrity", `<script src="https://cdn.example.net/app.js" integrity="sha384-abc123"></script>`},
		{"cross-origin link with integrity", `<link rel="stylesheet" href="https://cdn.example.net/app.css" integrity="sha384-abc123">`},
		{"non-stylesheet link", `<link rel="icon" href="https://cdn.example.net/favicon.ico">`},
		{"script with no src", `<script>console.log("inline")</script>`},
		{"no script or link tags", `<html><body><p>hello</p></body></html>`},
		{"empty body", ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.SRIChecker{}.CheckBody([]byte(tt.html), sriTargetURL)
			if len(findings) != 0 {
				t.Fatalf("CheckBody() returned %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestSRICheckerReportsEachOffendingTagIndependently(t *testing.T) {
	body := `
		<script src="https://cdn.example.net/a.js"></script>
		<script src="/same-origin.js"></script>
		<link rel="stylesheet" href="https://cdn.example.net/b.css">
	`
	findings := scanner.SRIChecker{}.CheckBody([]byte(body), sriTargetURL)
	if len(findings) != 2 {
		t.Fatalf("CheckBody() returned %d findings, want 2", len(findings))
	}
}

func TestSRICheckerHandlesUnparseableTargetURL(t *testing.T) {
	findings := scanner.SRIChecker{}.CheckBody([]byte(`<script src="https://cdn.example.net/a.js"></script>`), "://not-a-url")
	if findings != nil {
		t.Fatalf("CheckBody() with an unparseable target URL = %+v, want nil", findings)
	}
}

func TestRunAllBodyFansOutAcrossDefaultBodyCheckers(t *testing.T) {
	body := []byte(`<script src="https://cdn.example.net/a.js"></script>`)
	findings := scanner.RunAllBody(scanner.DefaultBodyCheckers(), body, sriTargetURL)
	if len(findings) != 1 {
		t.Fatalf("RunAllBody() returned %d findings, want 1", len(findings))
	}
}
