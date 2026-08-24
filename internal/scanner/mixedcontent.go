package scanner

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

const mixedContentHeader = "Mixed Content"

const mixedContentReference = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"

// mixedContentTags lists the elements whose src/href can load a resource of
// their own: img/script/link/iframe/audio/video are the tags browsers apply
// mixed-content blocking to, since each can fetch content outside the page's
// own TLS connection.
var mixedContentTags = map[string]bool{
	"img":    true,
	"script": true,
	"link":   true,
	"iframe": true,
	"audio":  true,
	"video":  true,
}

var mixedContentAttrs = map[string]bool{"src": true, "href": true}

// linkFetchingRels lists the rel values that make a <link> a subresource the
// browser actually fetches (and so applies mixed-content blocking to).
// Most rel values — canonical, alternate, author, license, search — are pure
// metadata the browser never dereferences, so treating every <link href>
// as mixed content would flag the canonical tag on most real https:// pages.
var linkFetchingRels = map[string]bool{
	"stylesheet":                   true,
	"icon":                         true,
	"apple-touch-icon":             true,
	"apple-touch-icon-precomposed": true,
	"manifest":                     true,
	"preload":                      true,
	"prefetch":                     true,
	"prerender":                    true,
}

// isFetchingLinkToken reports whether an https response would actually load
// this token's resource: every tag besides <link> in mixedContentTags always
// fetches its src, but a <link> only fetches href for a rel value in
// linkFetchingRels.
func isFetchingLinkToken(token html.Token) bool {
	if token.Data != "link" {
		return true
	}
	for _, attr := range token.Attr {
		if attr.Key != "rel" {
			continue
		}
		for _, rel := range strings.Fields(strings.ToLower(attr.Val)) {
			if linkFetchingRels[rel] {
				return true
			}
		}
	}
	return false
}

// MixedContentChecker scans an https:// response body for resource
// references that load over plain http:// instead. Those resources bypass
// TLS entirely, so a network attacker can tamper with or substitute them
// even though the page itself was served securely — the padlock in the
// address bar doesn't cover them.
//
// Unlike the header checkers, there's no StatusPass/StatusMissing case here:
// a clean page has nothing to flag, so it produces no findings at all,
// mirroring how BannerDisclosureChecker treats absence as the desired state.
type MixedContentChecker struct{}

var asciiWhitespaceStripper = strings.NewReplacer("\t", "", "\n", "", "\r", "")

func stripASCIIWhitespace(value string) string {
	return strings.TrimSpace(asciiWhitespaceStripper.Replace(value))
}

func (MixedContentChecker) Check(body io.Reader) []Finding {
	var findings []Finding
	tokenizer := html.NewTokenizer(body)
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			return findings
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !mixedContentTags[token.Data] || !isFetchingLinkToken(token) {
			continue
		}
		for _, attr := range token.Attr {
			if !mixedContentAttrs[attr.Key] {
				continue
			}
			// Browsers strip ASCII tab/newline/carriage-return from anywhere
			// in a URL before parsing its scheme (WHATWG URL spec), not just
			// the ends, so a value like "ht\ntp://" still resolves to plain
			// http:// even though a plain TrimSpace wouldn't catch it.
			value := stripASCIIWhitespace(attr.Val)
			if !strings.HasPrefix(strings.ToLower(value), "http://") {
				continue
			}
			findings = append(findings, Finding{
				Header:    mixedContentHeader,
				Status:    StatusWeak,
				Severity:  SeverityMedium,
				Reference: mixedContentReference,
				Message:   fmt.Sprintf("<%s %s=%q> loads over insecure http://, bypassing the page's TLS protection", token.Data, attr.Key, value),
			})
		}
	}
}
