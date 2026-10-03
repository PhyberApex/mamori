package scanner_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

// recordingTransport records the time every RoundTrip call arrives and
// returns a canned 200 response, so tests can assert on request spacing
// without a real server/network round trip in the mix.
type recordingTransport struct {
	mu    sync.Mutex
	times []time.Time
	hosts []string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.times = append(r.times, time.Now())
	r.hosts = append(r.hosts, req.URL.Host)
	r.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
}

func newRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext(%q) failed: %v", rawURL, err)
	}
	return req
}

// roundTrip issues req through rt and closes the response body, so test
// bodies don't have to repeat that bookkeeping around every RoundTrip call.
func roundTrip(t *testing.T, rt http.RoundTripper, req *http.Request) {
	t.Helper()
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() returned error: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("closing response body: %v", err)
	}
}

// doGet issues a GET through client, draining and closing the response body
// before returning so callers that only care about the error don't have to.
func doGet(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext(%q) failed: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func TestRateLimitedTransportDoesNotDelayFirstRequest(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewRateLimitedTransport(base, 1, time.Second)

	start := time.Now()
	roundTrip(t, rt, newRequest(t, "http://a.example/"))
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("first request to a host took %v, want ~0 (no burst delay)", elapsed)
	}
}

func TestRateLimitedTransportSpacesRequestsToSameHost(t *testing.T) {
	base := &recordingTransport{}
	const rate = 20.0 // one request every 50ms
	rt := scanner.NewRateLimitedTransport(base, rate, time.Second)

	for range 3 {
		roundTrip(t, rt, newRequest(t, "http://a.example/"))
	}

	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.times) != 3 {
		t.Fatalf("got %d requests, want 3", len(base.times))
	}
	want := time.Second / time.Duration(rate)
	for i := 1; i < len(base.times); i++ {
		if gap := base.times[i].Sub(base.times[i-1]); gap < want {
			t.Errorf("gap between request %d and %d = %v, want >= %v", i-1, i, gap, want)
		}
	}
}

func TestRateLimitedTransportDoesNotThrottleDifferentHosts(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewRateLimitedTransport(base, 1, time.Second) // 1/s: a same-host second request would wait ~1s

	start := time.Now()
	roundTrip(t, rt, newRequest(t, "http://a.example/"))
	roundTrip(t, rt, newRequest(t, "http://b.example/"))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("two requests to different hosts took %v, want ~0: a per-host limit must not throttle across hosts", elapsed)
	}
}

func TestRateLimitedTransportThrottlesSharedAcrossCallers(t *testing.T) {
	base := &recordingTransport{}
	const rate = 20.0
	rt := scanner.NewRateLimitedTransport(base, rate, time.Second)

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := rt.RoundTrip(newRequest(t, "http://a.example/"))
			if err != nil {
				t.Errorf("RoundTrip() returned error: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()

	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.times) != 3 {
		t.Fatalf("got %d requests, want 3", len(base.times))
	}
	// Order between concurrent callers isn't guaranteed, but however they
	// were interleaved, the limit is shared across all of them for the same
	// host: three requests at rate=20/s must span at least 2 intervals
	// start-to-finish.
	min, max := base.times[0], base.times[0]
	for _, ts := range base.times[1:] {
		if ts.Before(min) {
			min = ts
		}
		if ts.After(max) {
			max = ts
		}
	}
	want := 2 * (time.Second / time.Duration(rate))
	if span := max.Sub(min); span < want {
		t.Errorf("span across 3 concurrent requests to the same host = %v, want >= %v", span, want)
	}
}

func TestRateLimitedTransportWaitCanceledByContext(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewRateLimitedTransport(base, 1, time.Second)

	roundTrip(t, rt, newRequest(t, "http://a.example/"))

	ctx, cancel := context.WithCancel(context.Background())
	req := newRequest(t, "http://a.example/").WithContext(ctx)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("RoundTrip() error = %v, want context.Canceled while still queued behind the limiter", err)
	}
}

// TestRateLimitedTransportCanceledWaitDoesNotThrottleLaterRequest proves a
// request abandoned mid-queue releases the slot it reserved: a real request
// to the same host that comes right after must not be forced to wait out
// the canceled one's interval on top of its own.
func TestRateLimitedTransportCanceledWaitDoesNotThrottleLaterRequest(t *testing.T) {
	base := &recordingTransport{}
	const rate = 1.0 // interval = 1s
	rt := scanner.NewRateLimitedTransport(base, rate, time.Second)

	start := time.Now()
	roundTrip(t, rt, newRequest(t, "http://a.example/"))

	ctx, cancel := context.WithCancel(context.Background())
	canceledReq := newRequest(t, "http://a.example/").WithContext(ctx)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	resp, err := rt.RoundTrip(canceledReq)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RoundTrip() error = %v, want context.Canceled", err)
	}

	roundTrip(t, rt, newRequest(t, "http://a.example/"))
	// Without releasing the canceled request's reservation, the third
	// request would have to wait out two intervals from the first request
	// (the canceled request's slot, plus its own on top of it) — close to
	// 2s here. With the reservation released, it waits out only one, as if
	// the canceled request had never been attempted.
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("elapsed from the first request through the third = %v, want < 1.5s (~1 interval): the canceled request's reserved slot must be released, not charged on top of the next real request's own wait", elapsed)
	}
}

// TestRateLimitedTransportTinyRateDoesNotInvertIntoNoWait guards against a
// float64-to-time.Duration overflow: 1/rate seconds, converted to
// nanoseconds, exceeds math.MaxInt64 for a rate this small, which without
// clamping wraps into a bogus (often negative) interval and would make the
// limiter never wait at all — the opposite of what an extremely small rate
// asks for.
func TestRateLimitedTransportTinyRateDoesNotInvertIntoNoWait(t *testing.T) {
	base := &recordingTransport{}
	rt := scanner.NewRateLimitedTransport(base, 1e-10, time.Second)

	roundTrip(t, rt, newRequest(t, "http://a.example/"))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err := rt.RoundTrip(newRequest(t, "http://a.example/").WithContext(ctx))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RoundTrip() error = %v, want context.DeadlineExceeded: an extremely small rate must still throttle, not silently become unlimited", err)
	}
}

// TestRateLimitedTransportTimeoutExcludesLimiterWait is the core guarantee
// the issue calls for: a request queued behind the limiter for longer than
// Timeout must still succeed, because Timeout only starts counting once the
// limiter actually releases the request, never while it's waiting.
func TestRateLimitedTransportTimeoutExcludesLimiterWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	const rate = 2.0 // one request every 500ms
	const timeout = 100 * time.Millisecond
	rt := scanner.NewRateLimitedTransport(http.DefaultTransport, rate, timeout)
	client := &http.Client{Transport: rt}

	if err := doGet(t, client, srv.URL); err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	// The second request is forced to queue behind the limiter for ~500ms —
	// five times longer than Timeout — yet the server itself answers
	// instantly, so it must still succeed.
	if err := doGet(t, client, srv.URL); err != nil {
		t.Fatalf("second request failed: %v (queued-limiter wait must not count against -timeout)", err)
	}
}

// TestRateLimitedTransportTimeoutStillAppliesToSlowServer proves Timeout is
// still a real, enforced per-request deadline once the limiter has released
// the request — the previous test isn't passing merely because Timeout was
// accidentally disabled altogether.
func TestRateLimitedTransportTimeoutStillAppliesToSlowServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	rt := scanner.NewRateLimitedTransport(http.DefaultTransport, 1, 50*time.Millisecond)
	client := &http.Client{Transport: rt}

	if err := doGet(t, client, srv.URL); err == nil {
		t.Fatal("request to a server that never responds returned nil error, want a timeout error")
	}
}

// TestRateLimitedTransportTimeoutIsPerHopAcrossARedirect documents and
// locks in a deliberate consequence of excluding limiter-queue time from
// Timeout: since each hop of a redirect chain is a separate RoundTrip call,
// each gets its own fresh Timeout budget rather than sharing one budget for
// the whole chain the way http.Client.Timeout would. A chain whose combined
// hops exceed Timeout, but where no single hop does, must still succeed.
func TestRateLimitedTransportTimeoutIsPerHopAcrossARedirect(t *testing.T) {
	const perHopDelay = 60 * time.Millisecond
	const timeout = 100 * time.Millisecond // less than 2x perHopDelay

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perHopDelay)
	}))
	t.Cleanup(final.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perHopDelay)
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)

	rt := scanner.NewRateLimitedTransport(http.DefaultTransport, 1000, timeout) // rate high enough that queueing isn't a factor here
	client := &http.Client{Transport: rt}

	if err := doGet(t, client, redirecting.URL); err != nil {
		t.Errorf("GET through a 2-hop redirect with each hop under Timeout but their sum over it returned %v, want nil: Timeout applies per hop, not to the whole chain", err)
	}
}

func TestRateLimitedTransportThrottlesRedirectAgainstNewHost(t *testing.T) {
	var mu sync.Mutex
	var finalHits []time.Time
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		finalHits = append(finalHits, time.Now())
		mu.Unlock()
	}))
	t.Cleanup(final.Close)

	// Two distinct "originally typed" hosts that both redirect to the same
	// final host. If throttling were keyed by the original host instead of
	// the authority actually sent, these two would never be throttled
	// against each other.
	redirectA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(redirectA.Close)
	redirectB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(redirectB.Close)

	const rate = 10.0 // one request every 100ms
	rt := scanner.NewRateLimitedTransport(http.DefaultTransport, rate, time.Second)
	client := &http.Client{Transport: rt}

	if err := doGet(t, client, redirectA.URL); err != nil {
		t.Fatalf("request to redirectA failed: %v", err)
	}
	if err := doGet(t, client, redirectB.URL); err != nil {
		t.Fatalf("request to redirectB failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(finalHits) != 2 {
		t.Fatalf("final host received %d requests, want 2", len(finalHits))
	}
	want := time.Second / time.Duration(rate)
	if gap := finalHits[1].Sub(finalHits[0]); gap < want {
		t.Errorf("gap between the two redirected requests landing on the shared final host = %v, want >= %v: a redirect must be throttled against the host it lands on, not the one originally typed", gap, want)
	}
}
