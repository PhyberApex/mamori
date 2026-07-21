package scanner

import (
	"net/http"
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
	return checkPresence(
		headers,
		"Strict-Transport-Security",
		SeverityHigh,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
	)
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
	return checkPresence(
		headers,
		"X-Frame-Options",
		SeverityMedium,
		"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
	)
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
	return checkPresence(
		headers,
		"Referrer-Policy",
		SeverityLow,
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy",
	)
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
