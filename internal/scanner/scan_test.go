package scanner_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

var allSecurityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=63072000",
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"Content-Security-Policy":   "default-src 'self'",
	"Referrer-Policy":           "no-referrer",
}

func scanOne(t *testing.T, handler http.Handler) []scanner.Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	findings, err := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), []string{srv.URL})
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("Scan() returned %d findings, want 5", len(findings))
	}
	for _, f := range findings {
		if f.URL != srv.URL {
			t.Errorf("finding %s has URL %q, want %q", f.Header, f.URL, srv.URL)
		}
	}
	return findings
}

func assertAllStatus(t *testing.T, findings []scanner.Finding, want scanner.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Status != want {
			t.Errorf("%s status = %q, want %q", f.Header, f.Status, want)
		}
	}
}

func TestScanAllHeadersPresent(t *testing.T) {
	findings := scanOne(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range allSecurityHeaders {
			w.Header().Set(name, value)
		}
	}))
	assertAllStatus(t, findings, scanner.StatusPass)
}

func TestScanAllHeadersMissing(t *testing.T) {
	findings := scanOne(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	assertAllStatus(t, findings, scanner.StatusMissing)
}

func TestScanFallsBackToGETWhenHEADRejected(t *testing.T) {
	findings := scanOne(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		for name, value := range allSecurityHeaders {
			w.Header().Set(name, value)
		}
	}))
	assertAllStatus(t, findings, scanner.StatusPass)
}

func TestScanCoversMultipleURLs(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srvA.Close)
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srvB.Close)

	findings, err := scanner.Scan(t.Context(), srvA.Client(), scanner.DefaultCheckers(), []string{srvA.URL, srvB.URL})
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}
	if len(findings) != 10 {
		t.Fatalf("Scan() returned %d findings, want 10 (5 per URL)", len(findings))
	}
}
