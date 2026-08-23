package scanner

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type Checker interface {
	Check(headers http.Header) []Finding
}

func DefaultCheckers() []Checker {
	return []Checker{
		HSTSChecker{},
		ContentTypeOptionsChecker{},
		FrameOptionsChecker{},
		CSPChecker{},
		ReferrerPolicyChecker{},
		CookieChecker{},
	}
}

func RunAll(checkers []Checker, headers http.Header) []Finding {
	var findings []Finding
	for _, c := range checkers {
		findings = append(findings, c.Check(headers)...)
	}
	return findings
}

type HSTSChecker struct{}

func (HSTSChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Strict-Transport-Security",
		SeverityHigh,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
		hstsWeakness,
	)
}

// hstsWeakness flags an HSTS value whose max-age directive doesn't actually
// enforce HTTPS: missing/unparseable (browsers ignore the header without a
// valid max-age) or non-positive (max-age=0 tells the browser to stop
// enforcing HTTPS immediately, which is a request to disable HSTS).
func hstsWeakness(value string) (weak bool, message string) {
	for _, directive := range strings.Split(value, ";") {
		name, val, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		maxAge, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return true, fmt.Sprintf("max-age=%s is unparseable", strings.TrimSpace(val))
		}
		if maxAge <= 0 {
			return true, fmt.Sprintf("max-age=%d disables HSTS", maxAge)
		}
		return false, ""
	}
	return true, "max-age directive is missing"
}

type ContentTypeOptionsChecker struct{}

func (ContentTypeOptionsChecker) Check(headers http.Header) []Finding {
	return checkPresence(
		headers,
		"X-Content-Type-Options",
		SeverityMedium,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options",
	)
}

type FrameOptionsChecker struct{}

func (FrameOptionsChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"X-Frame-Options",
		SeverityMedium,
		"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
		frameOptionsWeakness,
	)
}

// frameOptionsWeakness flags any value other than DENY/SAMEORIGIN: modern
// browsers dropped support for ALLOW-FROM, and anything else is simply not
// a value the spec defines, so neither provides clickjacking protection.
func frameOptionsWeakness(value string) (weak bool, message string) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DENY", "SAMEORIGIN":
		return false, ""
	default:
		return true, fmt.Sprintf("%q is not DENY or SAMEORIGIN and provides no clickjacking protection", value)
	}
}

type CSPChecker struct{}

func (CSPChecker) Check(headers http.Header) []Finding {
	return checkPresence(
		headers,
		"Content-Security-Policy",
		SeverityHigh,
		"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
	)
}

type ReferrerPolicyChecker struct{}

func (ReferrerPolicyChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Referrer-Policy",
		SeverityLow,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy",
		referrerPolicyWeakness,
	)
}

// referrerPolicyWeakness flags unsafe-url, which explicitly sends the full
// URL (including any query string) to third parties on every cross-origin
// request — the opposite of what this header is for.
//
// A single Referrer-Policy value may be a comma-separated fallback list
// (e.g. "strict-origin-when-cross-origin, unsafe-url"), and per the
// Referrer Policy spec the browser applies the last *recognized* token in
// that list, not the value as a whole — so a strong-looking value can still
// resolve to unsafe-url if a weaker token follows it.
func referrerPolicyWeakness(value string) (weak bool, message string) {
	if strings.EqualFold(effectiveReferrerPolicy(value), "unsafe-url") {
		return true, "unsafe-url leaks the full URL, including query strings, to third parties on cross-origin requests"
	}
	return false, ""
}

var knownReferrerPolicies = map[string]bool{
	"no-referrer":                     true,
	"no-referrer-when-downgrade":      true,
	"origin":                          true,
	"origin-when-cross-origin":        true,
	"same-origin":                     true,
	"strict-origin":                   true,
	"strict-origin-when-cross-origin": true,
	"unsafe-url":                      true,
}

// effectiveReferrerPolicy returns the token a browser would actually apply
// from a (possibly comma-separated) Referrer-Policy value: later recognized
// tokens override earlier ones, and unrecognized tokens are skipped rather
// than treated as the effective policy.
func effectiveReferrerPolicy(value string) string {
	effective := ""
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if knownReferrerPolicies[strings.ToLower(token)] {
			effective = token
		}
	}
	return effective
}

const cookieReference = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"

// CookieChecker inspects every Set-Cookie header for the three flags that
// keep a cookie from being trivially stolen or forged: Secure, HttpOnly, and
// SameSite. Unlike the other checkers, a response with no cookies has
// nothing to protect, so no Set-Cookie header is not itself a finding — only
// a present-but-weak cookie is.
type CookieChecker struct{}

func (CookieChecker) Check(headers http.Header) []Finding {
	var findings []Finding
	for _, line := range headers.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		if err != nil {
			continue
		}
		findings = append(findings, cookieFindings(cookie)...)
	}
	return findings
}

// cookieFindings reports each weak attribute of a single cookie
// independently, mirroring how the other checkers emit one Finding per
// header rather than bundling unrelated weaknesses into one message.
func cookieFindings(cookie *http.Cookie) []Finding {
	var findings []Finding
	if !cookie.Secure {
		findings = append(findings, Finding{
			Header:    fmt.Sprintf("Set-Cookie: %s (Secure)", cookie.Name),
			Status:    StatusWeak,
			Severity:  SeverityHigh,
			Reference: cookieReference,
			Message:   fmt.Sprintf("cookie %q lacks the Secure flag and can be sent over plain HTTP", cookie.Name),
		})
	}
	if !cookie.HttpOnly {
		findings = append(findings, Finding{
			Header:    fmt.Sprintf("Set-Cookie: %s (HttpOnly)", cookie.Name),
			Status:    StatusWeak,
			Severity:  SeverityMedium,
			Reference: cookieReference,
			Message:   fmt.Sprintf("cookie %q lacks the HttpOnly flag and can be read by client-side JavaScript", cookie.Name),
		})
	}
	// Go only sets SameSite to Lax/Strict when the attribute is explicitly
	// present with a recognized value; a missing attribute leaves the zero
	// value, and an unrecognized value maps to SameSiteDefaultMode, so
	// anything other than Lax/Strict is either absent or explicit None.
	if cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode {
		findings = append(findings, Finding{
			Header:    fmt.Sprintf("Set-Cookie: %s (SameSite)", cookie.Name),
			Status:    StatusWeak,
			Severity:  SeverityMedium,
			Reference: cookieReference,
			Message:   fmt.Sprintf("cookie %q is missing SameSite=Strict/Lax and will be sent on cross-site requests", cookie.Name),
		})
	}
	return findings
}

func checkPresence(headers http.Header, name string, severity Severity, reference string) []Finding {
	status := StatusPass
	if strings.TrimSpace(headers.Get(name)) == "" {
		status = StatusMissing
	}
	return []Finding{{
		Header:    name,
		Status:    status,
		Severity:  severity,
		Reference: reference,
	}}
}

// checkValue extends checkPresence with a validator for headers where a
// present value can still be a functional no-op. Only a Finding that's
// already StatusPass gets validated — missing/empty values stay StatusMissing,
// since "provides no protection" and "isn't set" are different findings.
//
// A misconfigured proxy or CDN can cause a header to appear more than once
// in the same response; headers.Get only ever sees the first of those. We
// validate every non-blank occurrence and flag the finding as soon as any
// one of them is weak, rather than letting send order decide whether the
// scan reports pass or weak. A blank occurrence (e.g. a stray empty
// duplicate appended by some infra) is skipped rather than validated: it
// carries no value of its own to judge, and treating "" as a value would
// let it masquerade as a weak one, downgrading an otherwise strong header
// on the strength of infra noise.
func checkValue(headers http.Header, name string, severity Severity, reference string, validate func(value string) (weak bool, message string)) []Finding {
	findings := checkPresence(headers, name, severity, reference)
	if findings[0].Status != StatusPass {
		return findings
	}
	for _, value := range headers.Values(name) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if weak, message := validate(value); weak {
			findings[0].Status = StatusWeak
			findings[0].Message = message
			break
		}
	}
	return findings
}
