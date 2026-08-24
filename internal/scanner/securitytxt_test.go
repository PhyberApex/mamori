package scanner_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestSecurityTxtCheckerProbesWellKnownPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	scanner.SecurityTxtChecker{}.Check(t.Context(), srv.Client(), srv.URL)

	if gotPath != "/.well-known/security.txt" {
		t.Errorf("probed path = %q, want %q", gotPath, "/.well-known/security.txt")
	}
}

func TestSecurityTxtCheckerPassesOn2xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	findings := scanner.SecurityTxtChecker{}.Check(t.Context(), srv.Client(), srv.URL)
	if len(findings) != 1 {
		t.Fatalf("Check() returned %d findings, want 1", len(findings))
	}

	if findings[0].Status != scanner.StatusPass {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusPass)
	}
	if findings[0].Reference == "" {
		t.Error("Reference is empty, want a docs URL")
	}
}

func TestSecurityTxtCheckerFlagsNon2xxAsMissing(t *testing.T) {
	tests := []int{
		http.StatusNotFound,
		http.StatusMovedPermanently,
		http.StatusInternalServerError,
	}
	for _, status := range tests {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))

		findings := scanner.SecurityTxtChecker{}.Check(t.Context(), srv.Client(), srv.URL)
		if findings[0].Status != scanner.StatusMissing {
			t.Errorf("status %d: Status = %q, want %q", status, findings[0].Status, scanner.StatusMissing)
		}
		srv.Close()
	}
}

func TestSecurityTxtCheckerReportsErrorOnRequestFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := srv.URL
	srv.Close()

	findings := scanner.SecurityTxtChecker{}.Check(t.Context(), http.DefaultClient, unreachable)

	if findings[0].Status != scanner.StatusError {
		t.Errorf("Status = %q, want %q", findings[0].Status, scanner.StatusError)
	}
	if findings[0].Message == "" {
		t.Error("Message is empty, want the failure message")
	}
}

func TestSecurityTxtCheckerIgnoresTargetPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	scanner.SecurityTxtChecker{}.Check(t.Context(), srv.Client(), srv.URL+"/some/deep/path?query=1")

	if gotPath != "/.well-known/security.txt" {
		t.Errorf("probed path = %q, want %q (target's own path/query must not leak in)", gotPath, "/.well-known/security.txt")
	}
}

func TestSecurityTxtCheckerForcesHTTPSScheme(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// RFC 9116 section 3: "the file access MUST use the 'https' scheme".
	// Rewrite the TLS server's own https URL to look like an http target;
	// if the checker didn't force https, this would fail to reach the
	// TLS-only server at all.
	httpTarget := "http://" + strings.TrimPrefix(srv.URL, "https://")

	findings := scanner.SecurityTxtChecker{}.Check(t.Context(), srv.Client(), httpTarget)
	if findings[0].Status != scanner.StatusPass {
		t.Errorf("Status = %q, want %q (probe should have used https despite an http:// target)", findings[0].Status, scanner.StatusPass)
	}
}
