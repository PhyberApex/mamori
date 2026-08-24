package scanner_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestScanFlagsMixedContentOnHTTPSTarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), []string{srv.URL}, 1)

	var mixedContent []scanner.Finding
	for _, f := range findings {
		if f.Header == "Mixed Content" {
			mixedContent = append(mixedContent, f)
		}
	}
	if len(mixedContent) != 1 {
		t.Fatalf("Scan() returned %d Mixed Content findings, want 1: %+v", len(mixedContent), findings)
	}
	if mixedContent[0].URL != srv.URL {
		t.Errorf("URL = %q, want %q", mixedContent[0].URL, srv.URL)
	}
}

func TestScanSkipsMixedContentCheckOnHTTPTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://insecure.example.com/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), []string{srv.URL}, 1)

	for _, f := range findings {
		if f.Header == "Mixed Content" {
			t.Errorf("got Mixed Content finding on an http:// target, want none: %+v", f)
		}
	}
}
