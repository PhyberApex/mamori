package scanner

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// BodyChecker inspects the parsed HTML response body, unlike Checker which
// only inspects headers. Judging Subresource Integrity requires resolving
// each script/link tag's URL against the page's own origin, so a BodyChecker
// needs the target URL alongside the body.
type BodyChecker interface {
	CheckBody(body []byte, targetURL string) []Finding
}

func DefaultBodyCheckers() []BodyChecker {
	return []BodyChecker{SRIChecker{}}
}

func RunAllBody(checkers []BodyChecker, body []byte, targetURL string) []Finding {
	var findings []Finding
	for _, c := range checkers {
		findings = append(findings, c.CheckBody(body, targetURL)...)
	}
	return findings
}

const sriReference = "https://cheatsheetseries.owasp.org/cheatsheets/Subresource_Integrity_Cheat_Sheet.html"

// SRIChecker flags <script src> and <link rel="stylesheet" href> tags that
// load a cross-origin resource without an integrity attribute. Subresource
// Integrity lets the browser verify a fetched resource against a known hash
// before executing/applying it, which matters when that resource comes from
// somewhere the page owner doesn't fully control (e.g. a third-party CDN).
// Same-origin resources are served by the site itself and conventionally
// don't need it.
type SRIChecker struct{}

func (SRIChecker) CheckBody(body []byte, targetURL string) []Finding {
	base, err := url.Parse(targetURL)
	if err != nil {
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
			if f := sriFinding(n, base); f != nil {
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

// sriFinding judges a single element, returning nil for anything that isn't
// an in-scope tag, has no resource reference, is already covered by
// integrity, or resolves same-origin.
func sriFinding(n *html.Node, base *url.URL) *Finding {
	var attrName string
	switch n.Data {
	case "script":
		attrName = "src"
	case "link":
		if !hasAttrValue(n, "rel", "stylesheet") {
			return nil
		}
		attrName = "href"
	default:
		return nil
	}

	ref, ok := attrValue(n, attrName)
	if !ok || strings.TrimSpace(ref) == "" {
		return nil
	}
	if hasAttr(n, "integrity") {
		return nil
	}
	if !isCrossOrigin(base, ref) {
		return nil
	}

	return &Finding{
		Header:    fmt.Sprintf("<%s %s=%q>", n.Data, attrName, ref),
		Status:    StatusWeak,
		Severity:  SeverityLow,
		Reference: sriReference,
		Message:   fmt.Sprintf("%s=%q is loaded cross-origin without an integrity attribute", attrName, ref),
	}
}

// isCrossOrigin resolves ref against base the way a browser would (handling
// relative paths and protocol-relative URLs alike) and compares scheme+host,
// which is what determines origin for SRI purposes.
func isCrossOrigin(base *url.URL, ref string) bool {
	resolved, err := base.Parse(ref)
	if err != nil {
		return false
	}
	return !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host)
}

func attrValue(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// hasAttr reports whether key is present with a non-blank value: a blank
// integrity="" attribute provides no verification, same as omitting it.
func hasAttr(n *html.Node, key string) bool {
	v, ok := attrValue(n, key)
	return ok && strings.TrimSpace(v) != ""
}

func hasAttrValue(n *html.Node, key, want string) bool {
	v, ok := attrValue(n, key)
	return ok && strings.EqualFold(strings.TrimSpace(v), want)
}
