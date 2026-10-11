package scanner_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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
