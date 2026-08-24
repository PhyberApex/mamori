package scanner_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

// failGETTransport lets HEAD through to a real server but fails every GET,
// simulating a body fetch that breaks after the header fetch already
// succeeded (e.g. a transient failure or a WAF blocking the second request).
type failGETTransport struct {
	http.RoundTripper
}

func (t failGETTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		return nil, errors.New("simulated GET failure")
	}
	return t.RoundTripper.RoundTrip(req)
}

func mixedContentOnly(findings []scanner.Finding) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if f.Header == "Mixed Content" {
			out = append(out, f)
		}
	}
	return out
}

func TestScanFlagsMixedContentOnHTTPSTarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	mixedContent := mixedContentOnly(findings)
	if len(mixedContent) != 1 {
		t.Fatalf("Scan() returned %d Mixed Content findings, want 1: %+v", len(mixedContent), findings)
	}
	if mixedContent[0].URL != srv.URL {
		t.Errorf("URL = %q, want %q", mixedContent[0].URL, srv.URL)
	}
}

func TestScanReportsErrorWhenMixedContentBodyFetchFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	client := srv.Client()
	client.Transport = failGETTransport{RoundTripper: client.Transport}

	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	mixedContent := mixedContentOnly(findings)
	if len(mixedContent) != 1 {
		t.Fatalf("Scan() returned %d Mixed Content findings, want 1: %+v", len(mixedContent), findings)
	}
	if mixedContent[0].Status != scanner.StatusError {
		t.Errorf("Status = %q, want %q", mixedContent[0].Status, scanner.StatusError)
	}
	if mixedContent[0].Message == "" {
		t.Error("Message is empty, want the failure message")
	}
}

func TestScanSkipsMixedContentCheckOnHTTPTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	if got := mixedContentOnly(findings); len(got) != 0 {
		t.Errorf("got %d Mixed Content findings on an http:// target, want 0: %+v", len(got), got)
	}
}

func TestScanSkipsMixedContentCheckWithoutBodyCheckers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, []string{srv.URL}, 1)

	if got := mixedContentOnly(findings); len(got) != 0 {
		t.Errorf("got %d Mixed Content findings with no BodyCheckers configured, want 0: %+v", len(got), got)
	}
}

func TestScanSkipsMixedContentOnNonHTMLContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"src":"http://insecure.example.com/logo.png"}`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	if got := mixedContentOnly(findings); len(got) != 0 {
		t.Errorf("got %d Mixed Content findings on a non-HTML response, want 0: %+v", len(got), got)
	}
}

func TestScanSkipsMixedContentOnErrorStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	if got := mixedContentOnly(findings); len(got) != 0 {
		t.Errorf("got %d Mixed Content findings on a 503 response, want 0 (not the real page): %+v", len(got), got)
	}
}

func TestScanReusesFallbackGETBodyWhenHEADRejected(t *testing.T) {
	var gets atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gets.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	if got := mixedContentOnly(findings); len(got) != 1 {
		t.Fatalf("Scan() returned %d Mixed Content findings, want 1: %+v", len(got), findings)
	}
	if n := gets.Load(); n != 1 {
		t.Errorf("server received %d GET requests, want 1 (the HEAD-fallback body should be reused, not re-fetched)", n)
	}
}

func TestScanCapsMixedContentBodySize(t *testing.T) {
	// The insecure reference sits near the start of a body far larger than
	// maxBodyBytes, so capping the read must not turn into a read error —
	// content within the cap should still be found.
	var body strings.Builder
	body.WriteString(`<html><body><img src="http://insecure.example.com/logo.png">`)
	for body.Len() < 6*1024*1024 {
		body.WriteString("<!-- padding -->")
	}
	body.WriteString(`</body></html>`)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, body.String())
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)

	got := mixedContentOnly(findings)
	if len(got) != 1 {
		t.Fatalf("Scan() returned %d Mixed Content findings, want 1: %+v", len(got), findings)
	}
	if got[0].Status == scanner.StatusError {
		t.Errorf("a body larger than the cap should be truncated, not treated as a fetch error: %+v", got[0])
	}
}
