package scanner_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

var allSecurityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=63072000",
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"Content-Security-Policy":   "default-src 'self'",
	"Referrer-Policy":           "no-referrer",
	"Permissions-Policy":        "geolocation=()",
}

func scanOne(t *testing.T, handler http.Handler) []scanner.Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)
	if len(findings) != 6 {
		t.Fatalf("Scan() returned %d findings, want 6", len(findings))
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

	findings := scanner.Scan(t.Context(), srvA.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srvA.URL, srvB.URL}, 2)
	if len(findings) != 12 {
		t.Fatalf("Scan() returned %d findings, want 12 (6 per URL)", len(findings))
	}
}

func TestScanUnreachableTargetYieldsErrorFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := srv.URL
	srv.Close()

	findings := scanner.Scan(t.Context(), http.DefaultClient, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{unreachable}, 1)
	if len(findings) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1 error finding", len(findings))
	}
	f := findings[0]
	if f.Status != scanner.StatusError {
		t.Errorf("status = %q, want %q", f.Status, scanner.StatusError)
	}
	if f.URL != unreachable {
		t.Errorf("URL = %q, want %q", f.URL, unreachable)
	}
	if f.Message == "" {
		t.Error("Message is empty, want the failure message")
	}
}

func TestScanServerTimeoutYieldsErrorFinding(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	client := &http.Client{Timeout: 50 * time.Millisecond}
	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{srv.URL}, 1)
	if len(findings) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1 error finding", len(findings))
	}
	f := findings[0]
	if f.Status != scanner.StatusError {
		t.Errorf("status = %q, want %q", f.Status, scanner.StatusError)
	}
	if f.Message == "" {
		t.Error("Message is empty, want the timeout failure message")
	}
}

func TestScanReportsAllTargetsDespiteFailures(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(healthy.Close)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	findings := scanner.Scan(t.Context(), http.DefaultClient, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), []string{deadURL, healthy.URL}, 2)

	byURL := map[string][]scanner.Finding{}
	for _, f := range findings {
		byURL[f.URL] = append(byURL[f.URL], f)
	}
	if got := len(byURL[deadURL]); got != 1 {
		t.Errorf("dead target has %d findings, want 1 error finding", got)
	}
	if got := len(byURL[healthy.URL]); got != 6 {
		t.Errorf("healthy target has %d findings, want 6", got)
	}
}

func TestScanRunsTargetsConcurrently(t *testing.T) {
	const targets = 3
	var wg sync.WaitGroup
	wg.Add(targets)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Done()
		wg.Wait()
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	urls := []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c"}
	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), urls, targets)

	assertAllStatus(t, findings, scanner.StatusMissing)
	if len(findings) != targets*6 {
		t.Fatalf("Scan() returned %d findings, want %d", len(findings), targets*6)
	}
}

func TestScanBoundsConcurrencyToPoolSize(t *testing.T) {
	const workers = 2
	var inFlight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		// Lock-free running maximum: retry CompareAndSwap until our value is
		// stored or someone else stored a higher one (the standard Go idiom
		// for atomic max, since sync/atomic has no Max operation).
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	urls := make([]string, 6)
	for i := range urls {
		urls[i] = srv.URL + "/" + string(rune('a'+i))
	}
	scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), urls, workers)

	if p := peak.Load(); p > workers {
		t.Errorf("peak concurrent requests = %d, want at most %d", p, workers)
	}
}

func TestScanPreservesTargetOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	urls := []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c"}
	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), urls, 3)

	var seen []string
	for _, f := range findings {
		if len(seen) == 0 || seen[len(seen)-1] != f.URL {
			seen = append(seen, f.URL)
		}
	}
	if len(seen) != len(urls) {
		t.Fatalf("findings grouped into %d URL blocks, want %d contiguous blocks", len(seen), len(urls))
	}
	for i, url := range urls {
		if seen[i] != url {
			t.Errorf("URL block %d = %q, want %q (input order)", i, seen[i], url)
		}
	}
}
