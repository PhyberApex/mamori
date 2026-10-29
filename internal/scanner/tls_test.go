package scanner_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestCertExpiryCheckerCheck(t *testing.T) {
	respURL, _ := url.Parse("https://example.com")
	checker := scanner.NewCertExpiryChecker(30 * 24 * time.Hour)

	t.Run("nil state (no TLS) produces no finding", func(t *testing.T) {
		findings := checker.Check(nil, respURL)
		if len(findings) != 0 {
			t.Fatalf("Check() returned %d findings, want 0: %+v", len(findings), findings)
		}
	})

	t.Run("state with no peer certificates produces no finding", func(t *testing.T) {
		findings := checker.Check(&tls.ConnectionState{}, respURL)
		if len(findings) != 0 {
			t.Fatalf("Check() returned %d findings, want 0: %+v", len(findings), findings)
		}
	})

	t.Run("leaf expiring after the threshold passes", func(t *testing.T) {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{NotAfter: time.Now().Add(60 * 24 * time.Hour)},
		}}
		findings := checker.Check(state, respURL)
		if len(findings) != 1 {
			t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
		}
		if findings[0].Status != scanner.StatusPass {
			t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
		}
		if findings[0].Header != "TLS (certificate)" {
			t.Errorf("Header = %q, want %q", findings[0].Header, "TLS (certificate)")
		}
	})

	t.Run("leaf expiring within the threshold is insecure at medium severity", func(t *testing.T) {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{NotAfter: time.Now().Add(10 * 24 * time.Hour)},
		}}
		findings := checker.Check(state, respURL)
		if len(findings) != 1 {
			t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Status != scanner.StatusInsecure {
			t.Errorf("Status = %q, want %q", f.Status, scanner.StatusInsecure)
		}
		if f.Severity != scanner.SeverityMedium {
			t.Errorf("Severity = %q, want %q", f.Severity, scanner.SeverityMedium)
		}
		if f.Header != "TLS (certificate)" {
			t.Errorf("Header = %q, want %q", f.Header, "TLS (certificate)")
		}
		if f.Message == "" {
			t.Error("Message is empty, want an explanation of the upcoming expiry")
		}
	})

	t.Run("message states the threshold in days and the expiry in UTC", func(t *testing.T) {
		zone := time.FixedZone("CET", 3600)
		for _, tc := range []struct {
			days int
			unit string
		}{{30, "days"}, {1, "day"}} {
			notAfter := time.Now().Add(12 * time.Hour).In(zone).Truncate(time.Second)
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: notAfter}}}
			findings := scanner.NewCertExpiryChecker(time.Duration(tc.days)*24*time.Hour).Check(state, respURL)
			if len(findings) != 1 {
				t.Fatalf("Check() returned %d findings, want 1", len(findings))
			}
			want := fmt.Sprintf("certificate expires %s, within the %d-%s threshold", notAfter.UTC().Format(time.RFC3339), tc.days, tc.unit)
			if findings[0].Message != want {
				t.Errorf("Message = %q, want %q", findings[0].Message, want)
			}
		}
	})

	t.Run("leaf expiring exactly at the threshold is insecure", func(t *testing.T) {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{NotAfter: time.Now().Add(30 * 24 * time.Hour)},
		}}
		findings := checker.Check(state, respURL)
		if len(findings) != 1 || findings[0].Status != scanner.StatusInsecure {
			t.Fatalf("Check() = %+v, want 1 insecure finding (at-threshold expiry counts as within it)", findings)
		}
	})
}

func TestDefaultTLSCheckers(t *testing.T) {
	checkers := scanner.DefaultTLSCheckers(30 * 24 * time.Hour)
	if len(checkers) != 1 {
		t.Fatalf("DefaultTLSCheckers() returned %d checkers, want 1", len(checkers))
	}
}
