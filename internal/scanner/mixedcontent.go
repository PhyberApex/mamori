package scanner

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

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
		if !mixedContentTags[token.Data] {
			continue
		}
		for _, attr := range token.Attr {
			if !mixedContentAttrs[attr.Key] {
				continue
			}
			value := strings.TrimSpace(attr.Val)
			if !strings.HasPrefix(strings.ToLower(value), "http://") {
				continue
			}
			findings = append(findings, Finding{
				Header:    "Mixed Content",
				Status:    StatusWeak,
				Severity:  SeverityMedium,
				Reference: mixedContentReference,
				Message:   fmt.Sprintf("<%s %s=%q> loads over insecure http://, bypassing the page's TLS protection", token.Data, attr.Key, value),
			})
		}
	}
}
