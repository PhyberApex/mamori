package scanner

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"
)

// TLSChecker judges the judged response's TLS connection state, the
// category parallel to Checker (headers), BodyChecker (body), and
// PathChecker (a probed path's status code). state is nil for a response
// that didn't arrive over TLS at all — a target typed as http://, or one a
// redirect chain downgraded to it — in which case every TLSChecker produces
// no Finding, the same way TransportChecker's own Finding already covers
// that response. respURL is the final, post-redirect URL the response
// actually came from, the same value every other checker category receives.
type TLSChecker interface {
	Check(state *tls.ConnectionState, respURL *url.URL) []Finding
}

// DefaultTLSCheckers builds the default TLSChecker set: certificate-expiry
// only, following the Agent Brief's scope (protocol-version/weak-cipher
// checks are named as follow-up in docs/adr). expiryThreshold is the
// resolved -cert-expiry-days setting.
func DefaultTLSCheckers(expiryThreshold time.Duration) []TLSChecker {
	return []TLSChecker{NewCertExpiryChecker(expiryThreshold)}
}

// RunAllTLS runs every checker in checkers against state/respURL, the
// TLSChecker counterpart to RunAll/RunAllBody.
func RunAllTLS(checkers []TLSChecker, state *tls.ConnectionState, respURL *url.URL) []Finding {
	var findings []Finding
	for _, c := range checkers {
		findings = append(findings, c.Check(state, respURL)...)
	}
	return findings
}

const certExpiryReference = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"

// CertExpiryChecker flags a leaf certificate that will expire within
// threshold of now. An already-expired certificate is not a case this
// checker needs to handle: Go's client refuses the handshake before any
// response comes back, so that target already surfaces as the existing
// StatusError Finding rather than ever reaching Check.
type CertExpiryChecker struct {
	threshold time.Duration
}

// NewCertExpiryChecker builds a CertExpiryChecker that flags a certificate
// expiring within threshold of the current time.
func NewCertExpiryChecker(threshold time.Duration) CertExpiryChecker {
	return CertExpiryChecker{threshold: threshold}
}

// Check returns no Finding at all when state is nil (no TLS was involved) or
// carries no peer certificate — both mean there's no certificate expiry to
// judge. Otherwise it judges the leaf certificate: the first certificate in
// the chain the server presented is always the one the server identifies
// itself with (RFC 8446 §4.4.2), the rest being intermediates.
func (c CertExpiryChecker) Check(state *tls.ConnectionState, _ *url.URL) []Finding {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]

	status := StatusPass
	var message string
	if !leaf.NotAfter.After(time.Now().Add(c.threshold)) {
		status = StatusInsecure
		message = fmt.Sprintf("certificate expires %s, within the %s threshold", leaf.NotAfter.Format(time.RFC3339), c.threshold)
	}
	return []Finding{{
		Header:    "TLS (certificate)",
		Status:    status,
		Severity:  SeverityMedium,
		Reference: certExpiryReference,
		Message:   message,
	}}
}
