package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// legacyTLSVersions are the protocol versions TLSVersionProbe tries, oldest
// first, deprecated by RFC 8996.
var legacyTLSVersions = []struct {
	version uint16
	name    string
}{
	{tls.VersionTLS10, "TLS 1.0"},
	{tls.VersionTLS11, "TLS 1.1"},
}

// TLSVersionProbe is the opt-in dedicated handshake probe behind the
// "TLS (protocol)" Finding (see ADR-0005). Unlike a TLSChecker it does not
// judge the scan request's own connection: Go's client refuses to negotiate
// below TLS 1.2 by default, so it issues one extra handshake per legacy
// version against the judged response's host.
type TLSVersionProbe struct {
	// Timeout bounds each handshake (dial included). Zero means no bound
	// beyond the scan's own context.
	Timeout time.Duration
	// Wait, if non-nil, is called with the response URL's Host (the key
	// RateLimitedTransport throttles by) before each
	// handshake so the probe counts against -rate like every other request to that
	// host. It returns ctx's error if ctx is done first.
	Wait func(ctx context.Context, host string) error
}

// Probe judges respURL's host. It returns no Finding when respURL isn't
// HTTPS, and none when ctx is canceled mid-probe (scanTarget adds the
// "scan interrupted" Finding). A dial that fails before any handshake yields
// a single error Finding and no "TLS (protocol)" Finding.
func (p *TLSVersionProbe) Probe(ctx context.Context, respURL *url.URL) []Finding {
	if p == nil || respURL == nil || respURL.Scheme != "https" {
		return nil
	}
	port := respURL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(respURL.Hostname(), port)

	var accepted []string
	for _, v := range legacyTLSVersions {
		ok, err := p.handshake(ctx, respURL.Host, addr, respURL.Hostname(), v.version)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return []Finding{{Status: StatusError, Message: "TLS version probe failed: " + err.Error()}}
		}
		if ok {
			accepted = append(accepted, v.name)
		}
	}

	f := Finding{Header: "TLS (protocol)", Status: StatusPass, Severity: SeverityMedium, Reference: certExpiryReference}
	if len(accepted) > 0 {
		f.Status = StatusInsecure
		if len(accepted) == 1 {
			f.Message = "server accepts " + accepted[0] + ", deprecated by RFC 8996"
		} else {
			f.Message = "server accepts " + strings.Join(accepted, " and ") + ", both deprecated by RFC 8996"
		}
	}
	return []Finding{f}
}

// handshake reports whether the server at addr completes a handshake pinned
// to version. A non-nil error means the connection could not be established
// at all (nothing to judge); a failed handshake is a refusal, not an error.
// Certificate validity is out of scope here (CertExpiryChecker's job), hence
// InsecureSkipVerify: only the negotiated version is judged.
func (p *TLSVersionProbe) handshake(ctx context.Context, limiterHost, addr, serverName string, version uint16) (bool, error) {
	if p.Wait != nil {
		if err := p.Wait(ctx, limiterHost); err != nil {
			return false, err
		}
	}
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	client := tls.Client(conn, &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //nolint:gosec // only the negotiated version is judged; see doc comment
		ServerName:         serverName,
	})
	err = client.HandshakeContext(ctx)
	// A timeout mid-handshake says nothing about whether the version is
	// accepted, so it is a probe failure rather than a refusal.
	var ne net.Error
	if err != nil && (errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())) {
		return false, err
	}
	return err == nil, nil
}
