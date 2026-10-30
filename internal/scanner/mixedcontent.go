package scanner

import (
	"bytes"
	"fmt"
	"net/http"
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

// cspUpgradesInsecureRequests reports whether any of the enforced policies
// carries an upgrade-insecure-requests directive. The browser then rewrites
// every http:// subresource to https:// before fetching, so none is loaded
// as mixed content (CONTEXT.md, Applicable).
func cspUpgradesInsecureRequests(policies []string) bool {
	for _, raw := range policies {
		// A comma joins several policies into one header value.
		for _, directive := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' }) {
			fields := strings.Fields(directive)
			if len(fields) > 0 && strings.EqualFold(fields[0], "upgrade-insecure-requests") {
				return true
			}
		}
	}
	return false
}

// metaCSPUpgradesInsecureRequests reports whether any <meta
// http-equiv="Content-Security-Policy"> element in the document declares
// upgrade-insecure-requests. Report-Only has no meta form, so any such meta
// is enforced.
func metaCSPUpgradesInsecureRequests(doc *html.Node) bool {
	var policies []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			if eq, _ := attrValue(n, "http-equiv"); strings.EqualFold(strings.TrimSpace(eq), "Content-Security-Policy") {
				if content, ok := attrValue(n, "content"); ok {
					policies = append(policies, content)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return cspUpgradesInsecureRequests(policies)
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
// the first place. A page whose enforced Content-Security-Policy (header or
// meta tag) carries upgrade-insecure-requests is not judged either: the
// browser upgrades each such reference before fetching it.
type MixedContentChecker struct{}

func (MixedContentChecker) CheckBody(body []byte, headers http.Header, respURL *url.URL) []Finding {
	if respURL.Scheme != "https" {
		return nil
	}
	if cspUpgradesInsecureRequests(headers.Values("Content-Security-Policy")) {
		return nil
	}
	if doc, err := html.Parse(bytes.NewReader(body)); err == nil && metaCSPUpgradesInsecureRequests(doc) {
		return nil
	}
	return walkElements(body, func(n *html.Node) *Finding {
		return mixedContentFinding(n, respURL)
	})
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
