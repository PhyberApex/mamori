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
	"Strict-Transport-Security":    "max-age=63072000",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Content-Security-Policy":      "default-src 'self'",
	"Referrer-Policy":              "no-referrer",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Embedder-Policy": "require-corp",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "geolocation=()",
}

func scanOne(t *testing.T, handler http.Handler) []scanner.Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, nil)
	if len(findings) != 9 {
		t.Fatalf("Scan() returned %d findings, want 9", len(findings))
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

func TestScanSkipsBodyFetchWhenNoBodyCheckersConfigured(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
	}))
	t.Cleanup(srv.Close)

	scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, nil)
	if gotMethod != http.MethodHead {
		t.Errorf("request method = %q, want %q (HEAD should be tried first when no body checkers are configured)", gotMethod, http.MethodHead)
	}
}

func TestScanRunsBodyCheckersWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<script src="https://cdn.example.net/app.js"></script>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), nil, scanner.DefaultBodyCheckers(), []string{srv.URL}, 1, nil)
	if len(findings) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", f.Status, scanner.StatusWeak)
	}
	if f.URL != srv.URL {
		t.Errorf("URL = %q, want %q", f.URL, srv.URL)
	}
}

func TestScanFlagsMixedContentOnHTTPSTarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<img src="http://insecure.example.net/logo.png">`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), nil, scanner.DefaultBodyCheckers(), []string{srv.URL}, 1, nil)
	if len(findings) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.SeverityMedium {
		t.Errorf("Severity = %q, want %q", f.Severity, scanner.SeverityMedium)
	}
	if f.URL != srv.URL {
		t.Errorf("URL = %q, want %q", f.URL, srv.URL)
	}
}

func TestScanCombinesHeaderAndBodyCheckerFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`<script src="https://cdn.example.net/app.js"></script>`))
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), []scanner.Checker{scanner.ContentTypeOptionsChecker{}}, scanner.DefaultBodyCheckers(), []string{srv.URL}, 1, nil)
	if len(findings) != 2 {
		t.Fatalf("Scan() returned %d findings, want 2 (1 header + 1 body)", len(findings))
	}
	for _, f := range findings {
		if f.URL != srv.URL {
			t.Errorf("finding %s has URL %q, want %q", f.Header, f.URL, srv.URL)
		}
	}
}

func TestScanCoversMultipleURLs(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srvA.Close)
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srvB.Close)

	findings := scanner.Scan(t.Context(), srvA.Client(), scanner.DefaultCheckers(), nil, []string{srvA.URL, srvB.URL}, 2, nil)
	if len(findings) != 18 {
		t.Fatalf("Scan() returned %d findings, want 18 (9 per URL)", len(findings))
	}
}

func TestScanUnreachableTargetYieldsErrorFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := srv.URL
	srv.Close()

	findings := scanner.Scan(t.Context(), http.DefaultClient, scanner.DefaultCheckers(), nil, []string{unreachable}, 1, nil)
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
	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, nil)
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

	findings := scanner.Scan(t.Context(), http.DefaultClient, scanner.DefaultCheckers(), nil, []string{deadURL, healthy.URL}, 2, nil)

	byURL := map[string][]scanner.Finding{}
	for _, f := range findings {
		byURL[f.URL] = append(byURL[f.URL], f)
	}
	if got := len(byURL[deadURL]); got != 1 {
		t.Errorf("dead target has %d findings, want 1 error finding", got)
	}
	if got := len(byURL[healthy.URL]); got != 9 {
		t.Errorf("healthy target has %d findings, want 9", got)
	}
}

func TestScanRunsTargetsConcurrently(t *testing.T) {
	const targets = 3
	var wg sync.WaitGroup
	wg.Add(targets)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORSChecker's probe request follows the plain request for the same
		// target sequentially, not concurrently with it; only the plain
		// request (no Origin header) is part of the concurrency proof below.
		if r.Header.Get("Origin") != "" {
			return
		}
		wg.Done()
		wg.Wait()
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	urls := []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c"}
	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), nil, urls, targets, nil)

	assertAllStatus(t, findings, scanner.StatusMissing)
	if len(findings) != targets*9 {
		t.Fatalf("Scan() returned %d findings, want %d", len(findings), targets*9)
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
	scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, urls, workers, nil)

	if p := peak.Load(); p > workers {
		t.Errorf("peak concurrent requests = %d, want at most %d", p, workers)
	}
}

func TestScanSendsOriginProbeAndFlagsReflectedCORSWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}))
	t.Cleanup(srv.Close)

	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, nil)

	var corsFindings []scanner.Finding
	for _, f := range findings {
		if f.Header == "Access-Control-Allow-Origin" {
			corsFindings = append(corsFindings, f)
		}
	}
	if len(corsFindings) != 1 {
		t.Fatalf("got %d Access-Control-Allow-Origin findings, want 1 (proves the probe request with a synthetic Origin header was sent and reflected): %+v", len(corsFindings), findings)
	}
	if corsFindings[0].Status != scanner.StatusWeak {
		t.Errorf("Status = %q, want %q", corsFindings[0].Status, scanner.StatusWeak)
	}
}

func TestScanNoCORSHeadersProducesNoCORSFinding(t *testing.T) {
	findings := scanOne(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range allSecurityHeaders {
			w.Header().Set(name, value)
		}
	}))
	for _, f := range findings {
		if f.Header == "Access-Control-Allow-Origin" {
			t.Errorf("unexpected CORS finding on a response with no Access-Control headers: %+v", f)
		}
	}
}

func TestScanSkipsFailedProbeRatherThanErroringTarget(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			<-release
			return
		}
		for name, value := range allSecurityHeaders {
			w.Header().Set(name, value)
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	client := &http.Client{Timeout: 50 * time.Millisecond}
	findings := scanner.Scan(t.Context(), client, scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, nil)

	if len(findings) == 0 {
		t.Fatal("Scan() returned no findings, want the plain request's findings despite the probe request failing")
	}
	for _, f := range findings {
		if f.Status == scanner.StatusError {
			t.Errorf("got error finding %+v, want the failed probe request skipped rather than erroring the whole target", f)
		}
	}
}

func TestScanPreservesTargetOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	urls := []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c"}
	findings := scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, urls, 3, nil)

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

func TestScanAppliesCustomHeadersToRequests(t *testing.T) {
	var gotAuth, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
	}))
	t.Cleanup(srv.Close)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer xyz")
	headers.Set("Cookie", "session=abc")
	scanner.Scan(t.Context(), srv.Client(), scanner.DefaultCheckers(), nil, []string{srv.URL}, 1, headers)

	if gotAuth != "Bearer xyz" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer xyz")
	}
	if gotCookie != "session=abc" {
		t.Errorf("Cookie header = %q, want %q", gotCookie, "session=abc")
	}
}

func TestScanAppliesCustomHeadersWhenFetchingBody(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	t.Cleanup(srv.Close)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer xyz")
	scanner.Scan(t.Context(), srv.Client(), nil, scanner.DefaultBodyCheckers(), []string{srv.URL}, 1, headers)

	if gotAuth != "Bearer xyz" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer xyz")
	}
}
