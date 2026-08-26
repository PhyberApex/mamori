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
		COOPChecker{},
		COEPChecker{},
		CORPChecker{},
		CookieChecker{},
		PermissionsPolicyChecker{},
		BannerDisclosureChecker{},
		CORSChecker{},
		XSSProtectionChecker{},
		CacheControlChecker{},
	}
}

// OriginProber is implemented by Checkers whose Check method must be
// evaluated against the response to a dedicated probe request carrying a
// synthetic cross-origin Origin header, rather than the plain scan request
// every other Checker judges. Scan detects it with a type assertion and
// issues at most one such probe request per target, shared by every Checker
// in the set that implements it.
type OriginProber interface {
	Checker
	ProbesOrigin()
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
	return checkValue(
		headers,
		"X-Content-Type-Options",
		SeverityMedium,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options",
		contentTypeOptionsWeakness,
	)
}

// contentTypeOptionsWeakness flags any value other than nosniff: it's the
// only value this header defines, so anything else is not recognized by
// browsers and disables MIME-sniffing protection just like a missing header.
func contentTypeOptionsWeakness(value string) (weak bool, message string) {
	if strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		return false, ""
	}
	return true, fmt.Sprintf("%q is not nosniff and has no effect", value)
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
	return checkValue(
		headers,
		"Content-Security-Policy",
		SeverityHigh,
		"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
		cspWeakness,
	)
}

// cspWeakness flags a CSP value that's present but provides little real
// protection: 'unsafe-inline'/'unsafe-eval' in any directive re-enable the
// exact inline-script and string-to-code execution CSP exists to block, a
// bare "*" source allows loading that content from any origin, and a policy
// with neither object-src nor default-src leaves plugin content (e.g.
// Flash/PDF embeds) completely unrestricted — object-src falls back to
// default-src per spec, so only missing both is a gap.
func cspWeakness(value string) (weak bool, message string) {
	hasObjectSrc := false
	hasDefaultSrc := false
	for _, directive := range strings.Split(value, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		switch name {
		case "object-src":
			hasObjectSrc = true
		case "default-src":
			hasDefaultSrc = true
		}
		for _, source := range fields[1:] {
			switch strings.ToLower(source) {
			case "'unsafe-inline'":
				return true, fmt.Sprintf("%s allows 'unsafe-inline', which permits inline scripts/styles and defeats CSP's XSS protection", name)
			case "'unsafe-eval'":
				return true, fmt.Sprintf("%s allows 'unsafe-eval', which permits string-to-code execution (eval, Function, etc.)", name)
			case "*":
				return true, fmt.Sprintf("%s allows * as a source, permitting content from any origin", name)
			}
		}
	}
	if !hasObjectSrc && !hasDefaultSrc {
		return true, "missing both object-src and default-src, leaving plugin/legacy content unrestricted"
	}
	return false, ""
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

type COOPChecker struct{}

func (COOPChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Cross-Origin-Opener-Policy",
		SeverityMedium,
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
		coopWeakness,
	)
}

// coopWeakness flags unsafe-none, the default that provides no isolation
// from cross-origin openers/popups, and any value the spec doesn't define,
// which browsers don't recognize and so also provides no isolation — same
// treatment as a missing header in both cases.
func coopWeakness(value string) (weak bool, message string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "same-origin", "same-origin-allow-popups", "noopener-allow-popups":
		return false, ""
	case "unsafe-none":
		return true, "unsafe-none is the default and provides no isolation from cross-origin openers/popups"
	default:
		return true, fmt.Sprintf("%q is not a recognized Cross-Origin-Opener-Policy value and provides no isolation", value)
	}
}

type COEPChecker struct{}

func (COEPChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Cross-Origin-Embedder-Policy",
		SeverityLow,
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
		coepWeakness,
	)
}

// coepWeakness flags unsafe-none, the default that lets this page load any
// cross-origin resource without that resource opting in, and any value the
// spec doesn't define, which browsers don't recognize and so also provides
// no protection — same treatment as a missing header in both cases. Severity
// is fixed lower than the other Cross-Origin-* checkers: unlike those,
// leaving this header unset is often the deliberate, correct choice, since
// enabling it breaks embedding of any cross-origin resource that isn't
// itself CORP/CORS-compliant.
func coepWeakness(value string) (weak bool, message string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "require-corp", "credentialless":
		return false, ""
	case "unsafe-none":
		return true, "unsafe-none is the default and lets this page load any cross-origin resource without that resource opting in"
	default:
		return true, fmt.Sprintf("%q is not a recognized Cross-Origin-Embedder-Policy value and provides no protection", value)
	}
}

type CORPChecker struct{}

func (CORPChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Cross-Origin-Resource-Policy",
		SeverityMedium,
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
		corpWeakness,
	)
}

// corpWeakness flags cross-origin, which explicitly opts back out of the
// protection this header exists to provide, and any value the spec doesn't
// define, which browsers don't recognize and so also provides no
// protection — same treatment as a missing header in both cases.
func corpWeakness(value string) (weak bool, message string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "same-site", "same-origin":
		return false, ""
	case "cross-origin":
		return true, "cross-origin opts out of cross-origin resource protection"
	default:
		return true, fmt.Sprintf("%q is not same-site, same-origin, or cross-origin and provides no protection", value)
	}
}

const xssProtectionReference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"

// XSSProtectionChecker inverts the "more of the header is better" pattern
// every other Checker in this file follows. X-XSS-Protection controls a
// legacy browser XSS filter that current browsers have removed (Chrome 78+,
// Edge) or never implemented (Firefox), and *enabling* it is itself a
// documented exploit vector on browsers that still honor it — mode=block in
// particular has been used as an XS-Leak side-channel. So pass is exactly
// the explicit disable value "0"; any enabled or unrecognized value is weak;
// absence is missing (low severity — nudges toward the unambiguous "0"
// rather than trusting browser defaults).
type XSSProtectionChecker struct{}

func (XSSProtectionChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"X-XSS-Protection",
		SeverityLow,
		xssProtectionReference,
		xssProtectionWeakness,
	)
}

// xssProtectionEnabledMessage is shared by every recognized "enabled"
// variant (1, 1; mode=block, 1; report=<URI>) rather than split per
// directive: the fix is the same regardless of which enabled variant was
// used, so a per-directive message would only add noise.
const xssProtectionEnabledMessage = "enabling this legacy XSS filter is not a safe substitute for the explicit \"0\" disable: it has a documented history of exploitable behavior (including an XS-Leak side-channel via mode=block), and modern browsers (Chrome 78+, Edge, Firefox) have removed or never implemented the feature entirely"

func xssProtectionWeakness(value string) (weak bool, message string) {
	if value == "0" {
		return false, ""
	}
	if isEnabledXSSProtectionValue(value) {
		return true, xssProtectionEnabledMessage
	}
	return true, fmt.Sprintf("%q is not a recognized X-XSS-Protection value", value)
}

// isEnabledXSSProtectionValue reports whether value is "1" optionally
// followed by the directives the spec defines for the legacy filter
// (mode=block, report=<URI>). Anything else — a bare unrecognized token, or
// "1" combined with a directive this header doesn't define — falls through
// to the distinct "unrecognized value" message instead of being lumped in
// with the known-enabled variants.
func isEnabledXSSProtectionValue(value string) bool {
	directives := strings.Split(value, ";")
	if strings.TrimSpace(directives[0]) != "1" {
		return false
	}
	for _, directive := range directives[1:] {
		name, val, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "mode":
			if !strings.EqualFold(strings.TrimSpace(val), "block") {
				return false
			}
		case "report":
			if strings.TrimSpace(val) == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

const cacheControlReference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"

type CacheControlChecker struct{}

func (CacheControlChecker) Check(headers http.Header) []Finding {
	return checkValue(
		headers,
		"Cache-Control",
		SeverityMedium,
		cacheControlReference,
		cacheControlWeakness,
	)
}

// cacheControlWeakness flags a value that lacks a directive actually
// preventing storage: no-store and private are the only directives that keep
// a response out of shared/private caches respectively. no-cache alone only
// forces revalidation without preventing storage, and a bare public,
// max-age=N with nothing else, or a value with only unrecognized directives,
// all leave the response cacheable by any shared cache (proxy/CDN) in the
// path.
//
// Cache-Control's directives are a comma-separated list, unlike the
// semicolon-separated directives HSTS/CSP use, so parsing must split on
// commas.
func cacheControlWeakness(value string) (weak bool, message string) {
	for _, directive := range strings.Split(value, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "no-store", "private":
			return false, ""
		}
	}
	return true, fmt.Sprintf("%q contains neither no-store nor private and permits storage in shared caches", value)
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

// cookieAttributes lists the three flags CookieChecker judges, in the order
// findings are reported. Go only sets SameSite to Lax/Strict when the
// attribute is explicitly present with a recognized value; a missing
// attribute leaves the zero value, and an unrecognized value maps to
// SameSiteDefaultMode, so anything other than Lax/Strict is either absent
// or explicit None.
var cookieAttributes = []struct {
	name     string
	severity Severity
	weak     func(cookie *http.Cookie) bool
	message  string
}{
	{"Secure", SeverityHigh, func(c *http.Cookie) bool { return !c.Secure }, "lacks the Secure flag and can be sent over plain HTTP"},
	{"HttpOnly", SeverityMedium, func(c *http.Cookie) bool { return !c.HttpOnly }, "lacks the HttpOnly flag and can be read by client-side JavaScript"},
	{"SameSite", SeverityMedium, func(c *http.Cookie) bool {
		return c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode
	}, "is missing SameSite=Strict/Lax and will be sent on cross-site requests"},
}

// cookieFindings reports each weak attribute of a single cookie
// independently, mirroring how the other checkers emit one Finding per
// header rather than bundling unrelated weaknesses into one message.
func cookieFindings(cookie *http.Cookie) []Finding {
	var findings []Finding
	for _, attr := range cookieAttributes {
		if !attr.weak(cookie) {
			continue
		}
		findings = append(findings, Finding{
			Header:    fmt.Sprintf("Set-Cookie: %s (%s)", cookie.Name, attr.name),
			Status:    StatusWeak,
			Severity:  attr.severity,
			Reference: cookieReference,
			Message:   fmt.Sprintf("cookie %q %s", cookie.Name, attr.message),
		})
	}
	return findings
}

type PermissionsPolicyChecker struct{}

func (PermissionsPolicyChecker) Check(headers http.Header) []Finding {
	return checkPresence(
		headers,
		"Permissions-Policy",
		SeverityMedium,
		"https://owasp.org/www-project-secure-headers/#permissions-policy",
	)
}

const bannerDisclosureReference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"

// BannerDisclosureChecker flags the Server and X-Powered-By headers whenever
// they carry a value. There's no StatusPass/StatusMissing case here: absence
// is the desired state and isn't itself worth reporting, so a response with
// neither header produces no findings at all, mirroring how CookieChecker
// treats a response with no cookies as having nothing to protect.
type BannerDisclosureChecker struct{}

func (BannerDisclosureChecker) Check(headers http.Header) []Finding {
	var findings []Finding
	for _, name := range bannerHeaderNames {
		// A misconfigured proxy or CDN can append a blank duplicate of the
		// header instead of leaving the origin's alone; headers.Get would
		// only ever see whichever occurrence happens to be first and could
		// miss a later, disclosing one. Report the first non-blank value.
		value := firstNonBlankValue(headers, name)
		if value == "" {
			continue
		}
		findings = append(findings, Finding{
			Header:    name,
			Status:    StatusWeak,
			Severity:  SeverityLow,
			Reference: bannerDisclosureReference,
			Message:   fmt.Sprintf("%q reveals backend software/version info useful for fingerprinting the server", value),
		})
	}
	return findings
}

// bannerHeaderNames lists the headers BannerDisclosureChecker judges. Unlike
// the other checkers, presence rather than absence is the finding: both
// headers exist only to advertise backend software/version info, which is
// useful to an attacker fingerprinting the stack and useful to nobody else.
var bannerHeaderNames = []string{"Server", "X-Powered-By"}

// CORSProbeOrigin is the synthetic, definitely-foreign origin Scan sends as
// the Origin header of the extra probe request CORSChecker needs (see
// OriginProber). Any Access-Control-Allow-Origin that reflects it back, or a
// bare "*", is telling literally any origin on the internet it may read the
// response. Exported so callers (and tests) that need to recognize a
// reflected probe origin don't have to duplicate the literal.
const CORSProbeOrigin = "https://mamori-cors-probe.invalid"

const corsReference = "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"

// CORSChecker flags an Access-Control-Allow-Origin that accepts any origin —
// either by reflecting back whatever Origin was sent, or a bare "*" —
// together with Access-Control-Allow-Credentials: true. A reflected origin
// is directly exploitable: it lets any site on the internet read
// authenticated responses via a victim's browser. A bare wildcard is not —
// per the Fetch spec's CORS check, a browser refuses to honor "*" on a
// credentialed request at all — but it's still flagged at a lower severity,
// since it signals a server that doesn't understand its own CORS policy and
// offers no such protection to non-browser clients. A bare wildcard with no
// credentials, or a specific allow-listed origin that doesn't match the
// probe's, is either intentionally permissive or already origin-restricted,
// and isn't a finding on its own.
type CORSChecker struct{}

func (CORSChecker) Check(headers http.Header) []Finding {
	// Both comparisons below are byte-exact, not case-insensitive: per the
	// Fetch spec's CORS check, a browser only honors a reflected origin that
	// matches the serialized request origin exactly, and only honors
	// Access-Control-Allow-Credentials when its value is exactly "true". A
	// server that replies with different casing isn't actually exploitable
	// through a real browser, so flagging it would be a false positive.
	acao := firstNonBlankValue(headers, "Access-Control-Allow-Origin")
	if acao != "*" && acao != CORSProbeOrigin {
		return nil
	}
	if firstNonBlankValue(headers, "Access-Control-Allow-Credentials") != "true" {
		return nil
	}

	if acao == CORSProbeOrigin {
		return []Finding{{
			Header:    "Access-Control-Allow-Origin",
			Status:    StatusWeak,
			Severity:  SeverityHigh,
			Reference: corsReference,
			Message:   fmt.Sprintf("%q together with Access-Control-Allow-Credentials: true lets any site read authenticated responses via a victim's browser", acao),
		}}
	}

	// A literal "*" never reaches this severity via a spec-compliant
	// browser: the Fetch spec's CORS check only accepts "*" when the
	// request isn't credentialed, so a credentialed fetch against this
	// response fails the check and no browser ever exposes it to
	// cross-origin JS. Still a real misconfiguration worth surfacing, just
	// not one with the same exploitability as a reflected origin.
	return []Finding{{
		Header:    "Access-Control-Allow-Origin",
		Status:    StatusWeak,
		Severity:  SeverityMedium,
		Reference: corsReference,
		Message:   `"*" together with Access-Control-Allow-Credentials: true is a broken CORS configuration: compliant browsers won't honor the wildcard on a credentialed request, but non-browser clients enforce no such restriction`,
	}}
}

// ProbesOrigin marks CORSChecker as an OriginProber: Check must see the
// response to the synthetic-Origin probe request, not the plain scan
// request's headers.
func (CORSChecker) ProbesOrigin() {}

// firstNonBlankValue returns the first non-blank occurrence of a header,
// unlike headers.Get which only ever sees the first occurrence regardless of
// whether it's blank. A misconfigured proxy or CDN can prepend a blank
// duplicate instead of leaving the origin's header alone.
func firstNonBlankValue(headers http.Header, name string) string {
	for _, raw := range headers.Values(name) {
		if value := strings.TrimSpace(raw); value != "" {
			return value
		}
	}
	return ""
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
