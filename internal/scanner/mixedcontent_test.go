package scanner_test

import (
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

const mixedContentTargetURL = "https://example.com/"

func TestMixedContentCheckerFlagsInsecureReferences(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"img src", `<img src="http://insecure.example.net/logo.png">`},
		{"script src", `<script src="http://insecure.example.net/app.js"></script>`},
		{"link stylesheet href", `<link rel="stylesheet" href="http://insecure.example.net/app.css">`},
		{"link icon href", `<link rel="icon" href="http://insecure.example.net/favicon.ico">`},
		{"iframe src", `<iframe src="http://insecure.example.net/embed"></iframe>`},
		{"audio src", `<audio src="http://insecure.example.net/a.mp3"></audio>`},
		{"video src", `<video src="http://insecure.example.net/v.mp4"></video>`},
		{"uppercase scheme", `<img src="HTTP://insecure.example.net/logo.png">`},
		{"link with multiple rel tokens", `<link rel="preload stylesheet" href="http://insecure.example.net/app.css">`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.MixedContentChecker{}.CheckBody([]byte(tt.html), mixedContentTargetURL)
			if len(findings) != 1 {
				t.Fatalf("CheckBody() returned %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Status != scanner.StatusWeak {
				t.Errorf("Status = %q, want %q", f.Status, scanner.StatusWeak)
			}
			if f.Severity != scanner.SeverityMedium {
				t.Errorf("Severity = %q, want %q", f.Severity, scanner.SeverityMedium)
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

func TestMixedContentCheckerIgnoresSafeCases(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"https src", `<img src="https://secure.example.net/logo.png">`},
		{"protocol-relative src", `<img src="//secure.example.net/logo.png">`},
		{"relative src", `<script src="/app.js"></script>`},
		{"non-fetching link rel", `<link rel="canonical" href="http://insecure.example.net/page">`},
		{"tag with no src/href", `<script>console.log("inline")</script>`},
		{"no in-scope tags", `<html><body><p>hello</p></body></html>`},
		{"empty body", ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.MixedContentChecker{}.CheckBody([]byte(tt.html), mixedContentTargetURL)
			if len(findings) != 0 {
				t.Fatalf("CheckBody() returned %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestMixedContentCheckerSkipsNonHTTPSTarget(t *testing.T) {
	findings := scanner.MixedContentChecker{}.CheckBody([]byte(`<img src="http://insecure.example.net/logo.png">`), "http://example.com/")
	if findings != nil {
		t.Fatalf("CheckBody() on an http:// target = %+v, want nil (mixed content only applies to https:// pages)", findings)
	}
}

func TestMixedContentCheckerHandlesUnparseableTargetURL(t *testing.T) {
	findings := scanner.MixedContentChecker{}.CheckBody([]byte(`<img src="http://insecure.example.net/logo.png">`), "://not-a-url")
	if findings != nil {
		t.Fatalf("CheckBody() with an unparseable target URL = %+v, want nil", findings)
	}
}

func TestMixedContentCheckerReportsEachOffendingTagIndependently(t *testing.T) {
	body := `
		<img src="http://insecure.example.net/a.png">
		<img src="https://secure.example.net/b.png">
		<script src="http://insecure.example.net/c.js"></script>
	`
	findings := scanner.MixedContentChecker{}.CheckBody([]byte(body), mixedContentTargetURL)
	if len(findings) != 2 {
		t.Fatalf("CheckBody() returned %d findings, want 2: %+v", len(findings), findings)
	}
}

func TestRunAllBodyIncludesMixedContentByDefault(t *testing.T) {
	body := []byte(`<img src="http://insecure.example.net/logo.png">`)
	findings := scanner.RunAllBody(scanner.DefaultBodyCheckers(), body, mixedContentTargetURL)
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Errorf("RunAllBody(DefaultBodyCheckers()) = %+v, want a Mixed Content finding", findings)
	}
}
