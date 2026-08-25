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
	return []BodyChecker{SRIChecker{}, MixedContentChecker{}}
}

func RunAllBody(checkers []BodyChecker, body []byte, targetURL string) []Finding {
	var findings []Finding
	for _, c := range checkers {
		findings = append(findings, c.CheckBody(body, targetURL)...)
	}
	return findings
}

// walkElements parses body as HTML and calls judge on every element node,
// collecting each non-nil Finding it returns. It's the shared traversal
// every BodyChecker needs — parsing and walking the tree is identical across
// checkers; only how a single element is judged differs.
func walkElements(body []byte, judge func(*html.Node) *Finding) []Finding {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var findings []Finding
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if f := judge(n); f != nil {
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
	return walkElements(body, func(n *html.Node) *Finding {
		return sriFinding(n, base)
	})
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
		if !hasRelValue(n, "stylesheet") {
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

// hasRelValue reports whether want is one of the link's rel keywords: rel is
// spec'd as a space-separated token list (e.g. rel="preload stylesheet"), not
// a single value, so an exact-string match would miss valid stylesheet links.
func hasRelValue(n *html.Node, want string) bool {
	v, ok := attrValue(n, "rel")
	if !ok {
		return false
	}
	for _, token := range strings.Fields(v) {
		if strings.EqualFold(token, want) {
			return true
		}
	}
	return false
}
