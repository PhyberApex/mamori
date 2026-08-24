package scanner_test

import (
	"strings"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestMixedContentFlagsInsecureImgSrc(t *testing.T) {
	body := `<html><body><img src="http://insecure.example.com/logo.png"></body></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))

	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
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
		t.Error("Message is empty, want an explanation")
	}
}

func TestMixedContentFlagsEachInsecureTag(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="http://insecure.example.com/style.css"></head>
<body>
<script src="http://insecure.example.com/app.js"></script>
<iframe src="http://insecure.example.com/embed"></iframe>
<audio src="http://insecure.example.com/a.mp3"></audio>
<video src="http://insecure.example.com/v.mp4"></video>
</body></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 5 {
		t.Fatalf("Check() returned %d findings, want 5: %+v", len(findings), findings)
	}
}

func TestMixedContentIgnoresProtocolRelativeURL(t *testing.T) {
	body := `<html><body><img src="//secure.example.com/logo.png"></body></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 0 {
		t.Errorf("Check() returned %d findings, want 0 (protocol-relative URLs inherit the page scheme): %+v", len(findings), findings)
	}
}

func TestMixedContentIsCaseInsensitiveToScheme(t *testing.T) {
	body := `<html><body><img src="HTTP://insecure.example.com/logo.png"></body></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
}

func TestMixedContentIgnoresNonFetchingLinkRel(t *testing.T) {
	body := `<html><head><link rel="canonical" href="http://insecure.example.com/page"></head></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 0 {
		t.Errorf("Check() returned %d findings, want 0 (rel=canonical is never fetched by the browser): %+v", len(findings), findings)
	}
}

func TestMixedContentFlagsFetchingLinkRel(t *testing.T) {
	body := `<html><head><link rel="icon" href="http://insecure.example.com/favicon.ico"></head></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
}

func TestMixedContentDetectsSchemeWithEmbeddedNewline(t *testing.T) {
	// Browsers strip ASCII tab/newline/CR from anywhere in a URL before
	// parsing it, so this still resolves to http://insecure.example.com/x.
	body := "<html><body><img src=\"ht\ntp://insecure.example.com/x.png\"></body></html>"
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
	}
}

func TestMixedContentAllSecureProducesNoFindings(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="https://secure.example.com/style.css"></head>
<body><img src="https://secure.example.com/logo.png"><script src="/relative.js"></script></body></html>`
	findings := scanner.MixedContentChecker{}.Check(strings.NewReader(body))
	if len(findings) != 0 {
		t.Errorf("Check() returned %d findings, want 0: %+v", len(findings), findings)
	}
}
