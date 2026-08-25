package scanner

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const mixedContentReference = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"

// mixedContentAttrs maps each in-scope element to the attribute holding its
// resource reference. link is excluded here and handled separately, since
// only some of its rel values are actually fetched by the browser (see
// mixedContentLinkRels).
var mixedContentAttrs = map[string]string{
	"img":    "src",
	"script": "src",
	"iframe": "src",
	"audio":  "src",
	"video":  "src",
	"link":   "href",
}

// mixedContentLinkRels lists the rel values that make a <link> a subresource
// the browser actually fetches, and so applies mixed-content blocking to.
// Most rel values (canonical, alternate, author, license, search, ...) are
// pure metadata the browser never dereferences, so treating every <link
// href> as mixed content would flag the canonical tag on most real https://
// pages.
var mixedContentLinkRels = []string{
	"stylesheet",
	"icon",
	"apple-touch-icon",
	"apple-touch-icon-precomposed",
	"manifest",
	"preload",
	"prefetch",
	"prerender",
}

// MixedContentChecker flags resources an https:// page loads over plain
// http:// instead. Those resources bypass TLS entirely, so a network
// attacker can tamper with or substitute them even though the page itself
// was served securely — the padlock in the address bar doesn't cover them.
//
// There's no StatusPass case here: a clean page has nothing to flag, so it
// produces no findings at all, mirroring how BannerDisclosureChecker treats
// absence as the desired state. The check only applies to https:// targets —
// an http:// target has no TLS guarantee for mixed content to undermine in
// the first place.
type MixedContentChecker struct{}

func (MixedContentChecker) CheckBody(body []byte, targetURL string) []Finding {
	base, err := url.Parse(targetURL)
	if err != nil || base.Scheme != "https" {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var findings []Finding
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if f := mixedContentFinding(n, base); f != nil {
				findings = append(findings, *f)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

// mixedContentFinding judges a single element, returning nil for anything
// that isn't an in-scope tag, has no resource reference, or resolves to a
// scheme other than http (relative and protocol-relative references inherit
// the page's own https scheme, so they resolve safe).
func mixedContentFinding(n *html.Node, base *url.URL) *Finding {
	attrName, ok := mixedContentAttrs[n.Data]
	if !ok {
		return nil
	}
	if n.Data == "link" && !hasAnyRelValue(n, mixedContentLinkRels) {
		return nil
	}

	ref, ok := attrValue(n, attrName)
	if !ok || strings.TrimSpace(ref) == "" {
		return nil
	}
	resolved, err := base.Parse(ref)
	if err != nil || !strings.EqualFold(resolved.Scheme, "http") {
		return nil
	}

	return &Finding{
		Header:    fmt.Sprintf("<%s %s=%q>", n.Data, attrName, ref),
		Status:    StatusWeak,
		Severity:  SeverityMedium,
		Reference: mixedContentReference,
		Message:   fmt.Sprintf("%s=%q loads over insecure http://, bypassing the page's TLS protection", attrName, ref),
	}
}

// hasAnyRelValue reports whether n's rel attribute contains any of want, per
// hasRelValue's space-separated-token-list handling.
func hasAnyRelValue(n *html.Node, want []string) bool {
	for _, w := range want {
		if hasRelValue(n, w) {
			return true
		}
	}
	return false
}
