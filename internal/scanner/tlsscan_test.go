package scanner_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

// newTLSServerExpiringAt starts an httptest TLS server presenting a
// self-signed leaf certificate whose NotAfter is notAfter. Providing
// srv.TLS.Certificates before StartTLS makes httptest both serve this
// certificate and trust it for srv.Client(), so Scan sees a real
// *tls.ConnectionState carrying it, the same as it would for any other
// HTTPS target — no need to fake tls.ConnectionState by hand.
func newTLSServerExpiringAt(t *testing.T, notAfter time.Time) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestScanCertExpiryChecker covers acceptance criteria 3-5 of issue #122:
// pass when the leaf certificate expires after the threshold, insecure at
// medium severity when it expires at or before the threshold, and no
// finding at all for a plain-HTTP response.
func TestScanCertExpiryChecker(t *testing.T) {
	const threshold = 30 * 24 * time.Hour
	tlsCheckers := scanner.DefaultTLSCheckers(threshold)

	t.Run("certificate expiring after the threshold passes", func(t *testing.T) {
		srv := newTLSServerExpiringAt(t, time.Now().Add(60*24*time.Hour))

		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, tlsCheckers, []string{srv.URL}, 1, nil)
		if len(findings) != 1 {
			t.Fatalf("Scan() returned %d findings, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Header != "TLS (certificate)" || f.Status != scanner.StatusPass {
			t.Fatalf("finding = %+v, want Header %q Status %q", f, "TLS (certificate)", scanner.StatusPass)
		}
	})

	t.Run("certificate expiring within the threshold is insecure", func(t *testing.T) {
		srv := newTLSServerExpiringAt(t, time.Now().Add(10*24*time.Hour))

		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, tlsCheckers, []string{srv.URL}, 1, nil)
		if len(findings) != 1 {
			t.Fatalf("Scan() returned %d findings, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Header != "TLS (certificate)" || f.Status != scanner.StatusInsecure || f.Severity != scanner.SeverityMedium {
			t.Fatalf("finding = %+v, want Header %q Status %q Severity %q", f, "TLS (certificate)", scanner.StatusInsecure, scanner.SeverityMedium)
		}
	})

	t.Run("plain HTTP produces no finding from this checker", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(srv.Close)

		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, tlsCheckers, []string{srv.URL}, 1, nil)
		if len(findings) != 0 {
			t.Fatalf("Scan() returned %d findings, want 0 (plain HTTP has no TLS state): %+v", len(findings), findings)
		}
	})
}

// newTLSServerWithVersions starts an httptest TLS server whose accepted
// protocol range is [min, max]. Setting MinVersion explicitly is what lets a
// Go server speak TLS 1.0/1.1 at all.
func newTLSServerWithVersions(t *testing.T, min, max uint16) *httptest.Server {
	t.Helper()
	srv := newTLSServerExpiringAt(t, time.Now().Add(365*24*time.Hour))
	srv.TLS.MinVersion = min
	srv.TLS.MaxVersion = max
	return srv
}

func TestScanTLSVersionProbe(t *testing.T) {
	probe := scanner.WithTLSVersionProbe(&scanner.TLSVersionProbe{Timeout: 5 * time.Second})

	find := func(fs []scanner.Finding) *scanner.Finding {
		for i := range fs {
			if fs[i].Header == "TLS (protocol)" {
				return &fs[i]
			}
		}
		return nil
	}

	t.Run("server accepting both legacy versions is insecure", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS10, tls.VersionTLS13)
		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, probe)
		f := find(findings)
		if f == nil {
			t.Fatalf("no TLS (protocol) finding: %+v", findings)
		}
		want := "server accepts TLS 1.0 and TLS 1.1, both deprecated by RFC 8996"
		if f.Status != scanner.StatusInsecure || f.Severity != scanner.SeverityMedium || f.Message != want {
			t.Fatalf("finding = %+v, want insecure/medium %q", f, want)
		}
		if f.URL != srv.URL {
			t.Errorf("URL = %q, want %q", f.URL, srv.URL)
		}
	})

	t.Run("server accepting only TLS 1.1 names only it", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS11, tls.VersionTLS11)
		srv.TLS.MaxVersion = tls.VersionTLS12
		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, probe)
		f := find(findings)
		if f == nil || f.Status != scanner.StatusInsecure || !strings.Contains(f.Message, "TLS 1.1") || strings.Contains(f.Message, "TLS 1.0") {
			t.Fatalf("finding = %+v, want insecure naming only TLS 1.1", f)
		}
	})

	t.Run("modern server passes", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS12, tls.VersionTLS13)
		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, probe)
		f := find(findings)
		if f == nil || f.Status != scanner.StatusPass {
			t.Fatalf("finding = %+v, want pass", f)
		}
	})

	t.Run("disabled by default", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS10, tls.VersionTLS13)
		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil)
		if f := find(findings); f != nil {
			t.Fatalf("unexpected finding without the probe: %+v", f)
		}
	})

	t.Run("plain HTTP produces no finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(srv.Close)
		findings := scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, probe)
		if len(findings) != 0 {
			t.Fatalf("findings = %+v, want none", findings)
		}
	})

	t.Run("unreachable host yields a probe-failed error and no protocol finding", func(t *testing.T) {
		u, _ := url.Parse("https://127.0.0.1:1/")
		p := &scanner.TLSVersionProbe{Timeout: time.Second}
		fs := p.Probe(t.Context(), u)
		if len(fs) != 1 || fs[0].Status != scanner.StatusError || !strings.HasPrefix(fs[0].Message, "TLS version probe failed: ") || fs[0].Header == "TLS (protocol)" {
			t.Fatalf("findings = %+v, want one probe-failed error", fs)
		}
	})

	t.Run("canceled context yields scan interrupted", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS10, tls.VersionTLS13)
		ctx, cancel := context.WithCancel(t.Context())
		p := &scanner.TLSVersionProbe{Timeout: 5 * time.Second, Wait: func(context.Context, string) error {
			cancel()
			return ctx.Err()
		}}
		findings := scanner.Scan(ctx, srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, scanner.WithTLSVersionProbe(p))
		var interrupted bool
		for _, f := range findings {
			if f.Header == "TLS (protocol)" {
				t.Fatalf("unexpected protocol finding: %+v", f)
			}
			if f.Status == scanner.StatusError && f.Message == "scan interrupted" {
				interrupted = true
			}
		}
		if !interrupted {
			t.Fatalf("findings = %+v, want scan interrupted", findings)
		}
	})

	t.Run("each handshake waits on the limiter", func(t *testing.T) {
		srv := newTLSServerWithVersions(t, tls.VersionTLS12, tls.VersionTLS13)
		var waits int
		p := &scanner.TLSVersionProbe{Timeout: 5 * time.Second, Wait: func(_ context.Context, host string) error {
			waits++
			return nil
		}}
		scanner.Scan(t.Context(), srv.Client(), nil, nil, nil, nil, []string{srv.URL}, 1, nil, scanner.WithTLSVersionProbe(p))
		if waits != 2 {
			t.Fatalf("waits = %d, want 2", waits)
		}
	})
}

func TestTLSVersionProbeHandshakeTimeoutIsAProbeFailure(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	u, _ := url.Parse("https://" + ln.Addr().String() + "/")
	fs := (&scanner.TLSVersionProbe{Timeout: 100 * time.Millisecond}).Probe(t.Context(), u)
	if len(fs) != 1 || fs[0].Status != scanner.StatusError || fs[0].Header == "TLS (protocol)" {
		t.Fatalf("findings = %+v, want one probe-failed error, not a protocol pass", fs)
	}
}
