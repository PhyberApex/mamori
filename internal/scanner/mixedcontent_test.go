package scanner_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

var mixedContentTargetURL, _ = url.Parse("https://example.com/")

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
			findings := scanner.MixedContentChecker{}.CheckBody([]byte(tt.html), nil, mixedContentTargetURL)
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
			findings := scanner.MixedContentChecker{}.CheckBody([]byte(tt.html), nil, mixedContentTargetURL)
			if len(findings) != 0 {
				t.Fatalf("CheckBody() returned %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestMixedContentCheckerSkipsNonHTTPSTarget(t *testing.T) {
	httpTargetURL, err := url.Parse("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	findings := scanner.MixedContentChecker{}.CheckBody([]byte(`<img src="http://insecure.example.net/logo.png">`), nil, httpTargetURL)
	if findings != nil {
		t.Fatalf("CheckBody() on an http:// target = %+v, want nil (mixed content only applies to https:// pages)", findings)
	}
}

func TestMixedContentCheckerReportsEachOffendingTagIndependently(t *testing.T) {
	body := `
		<img src="http://insecure.example.net/a.png">
		<img src="https://secure.example.net/b.png">
		<script src="http://insecure.example.net/c.js"></script>
	`
	findings := scanner.MixedContentChecker{}.CheckBody([]byte(body), nil, mixedContentTargetURL)
	if len(findings) != 2 {
		t.Fatalf("CheckBody() returned %d findings, want 2: %+v", len(findings), findings)
	}
}

func TestRunAllBodyIncludesMixedContentByDefault(t *testing.T) {
	body := []byte(`<img src="http://insecure.example.net/logo.png">`)
	findings := scanner.RunAllBody(scanner.DefaultBodyCheckers(), body, nil, mixedContentTargetURL)
	if len(findings) != 1 {
		t.Fatalf("RunAllBody() returned %d findings, want 1", len(findings))
	}
	if findings[0].Severity != scanner.SeverityMedium {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, scanner.SeverityMedium)
	}
}

func TestMixedContentSilentWhenUpgradeInsecureRequests(t *testing.T) {
	img := `<img src="http://cdn.example.com/a.png">`
	tests := map[string]struct {
		html    string
		headers http.Header
	}{
		"meta tag":            {`<html><head><meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests"></head><body>` + img + `</body></html>`, nil},
		"meta tag mixed case": {`<meta http-equiv="content-security-policy" content="default-src 'self'; Upgrade-Insecure-Requests">` + img, nil},
		"header":              {img, http.Header{"Content-Security-Policy": {"upgrade-insecure-requests"}}},
		"header among others": {img, http.Header{"Content-Security-Policy": {"default-src 'self'; UPGRADE-INSECURE-REQUESTS"}}},
		"header comma policy": {img, http.Header{"Content-Security-Policy": {"default-src 'self', upgrade-insecure-requests"}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := (scanner.MixedContentChecker{}).CheckBody([]byte(tt.html), tt.headers, mixedContentTargetURL); len(got) != 0 {
				t.Fatalf("CheckBody() = %+v, want none", got)
			}
		})
	}
}

func TestMixedContentStillFlaggedWithoutEnforcedUpgrade(t *testing.T) {
	img := `<img src="http://cdn.example.com/a.png">`
	tests := map[string]struct {
		html    string
		headers http.Header
	}{
		"report-only header":    {img, http.Header{"Content-Security-Policy-Report-Only": {"upgrade-insecure-requests"}}},
		"unrelated directive":   {img, http.Header{"Content-Security-Policy": {"default-src 'self'"}}},
		"directive as value":    {img, http.Header{"Content-Security-Policy": {"default-src upgrade-insecure-requests"}}},
		"meta other http-equiv": {`<meta http-equiv="refresh" content="upgrade-insecure-requests">` + img, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := (scanner.MixedContentChecker{}).CheckBody([]byte(tt.html), tt.headers, mixedContentTargetURL); len(got) != 1 {
				t.Fatalf("CheckBody() returned %d findings, want 1: %+v", len(got), got)
			}
		})
	}
}
