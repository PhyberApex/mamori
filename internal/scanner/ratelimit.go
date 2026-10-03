package scanner

import (
	"context"
	"io"
	"math"
	"net/http"
	"sync"
	"time"
)

// hostLimiter enforces a minimum spacing between consecutive requests to the
// same host, shared for the limiter's whole lifetime rather than reset per
// target, since multiple targets can resolve to the same host. There is no
// burst allowance: a host that has gone idle doesn't bank up credit for a
// faster-than-rate burst later, it simply isn't delayed on its next request
// either way. The zero value is not usable; construct with newHostLimiter.
type hostLimiter struct {
	interval time.Duration

	mu   sync.Mutex
	next map[string]time.Time
}

// newHostLimiter builds a hostLimiter pacing each host to rate requests per
// second. rate must be > 0 — a disabled (zero) rate is represented by not
// constructing a RateLimitedTransport at all, not by a hostLimiter with an
// infinite interval.
func newHostLimiter(rate float64) *hostLimiter {
	// A rate small enough that one request every 1/rate seconds overflows
	// time.Duration's int64 nanoseconds (e.g. rate below ~1e-10) would wrap
	// into a bogus, often negative, interval instead of "wait a very long
	// time" — clamping to the largest representable Duration keeps it an
	// extremely long wait instead of silently becoming no wait at all.
	ns := float64(time.Second) / rate
	interval := time.Duration(math.MaxInt64)
	if ns < float64(math.MaxInt64) {
		interval = time.Duration(ns)
	}
	return &hostLimiter{
		interval: interval,
		next:     make(map[string]time.Time),
	}
}

// wait blocks until it is host's turn to send its next request, returning
// ctx's error if ctx is done first. Reserving host's next slot happens under
// the lock before the actual waiting, so concurrent callers racing for the
// same host queue up in the order they reserved rather than ever computing
// the same slot twice. If ctx is done before the reserved slot arrives, the
// reservation is released (see release) so a request that's abandoned
// mid-queue doesn't go on throttling whichever real request comes next.
func (l *hostLimiter) wait(ctx context.Context, host string) error {
	l.mu.Lock()
	now := time.Now()
	start := l.next[host]
	if start.Before(now) {
		start = now
	}
	reserved := start.Add(l.interval)
	l.next[host] = reserved
	l.mu.Unlock()

	d := start.Sub(now)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		l.release(host, reserved)
		return ctx.Err()
	}
}

// release undoes the reservation wait made for host when its caller gave up
// before it came due, but only while reserved is still host's current slot:
// if another call has since reserved a later slot on top of it, that slot
// is still waiting for reserved to clear and rolling it back would corrupt
// that caller's ordering instead.
func (l *hostLimiter) release(host string, reserved time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next[host].Equal(reserved) {
		l.next[host] = reserved.Add(-l.interval)
	}
}

// RateLimitedTransport wraps another http.RoundTripper so that every request
// it sends is throttled against a per-host limiter before being handed to
// Base — including each individual hop of a redirect chain, since
// http.Client's own Do loop calls RoundTrip again for every hop. The host a
// request is throttled against is req.URL.Host, the authority of the
// request actually being sent for that hop, not whatever host the caller
// originally targeted, so a redirect that lands on a different host is
// throttled against that new host rather than the one the user typed.
//
// Timeout bounds each individual request this transport sends, counted from
// the moment the limiter releases it rather than from when RoundTrip was
// first called, so time spent queued behind the limiter never eats into the
// time available for the request itself.
type RateLimitedTransport struct {
	Base    http.RoundTripper
	Timeout time.Duration

	limiter *hostLimiter
}

// NewRateLimitedTransport returns a RateLimitedTransport that paces requests
// to at most rate per second per host, enforcing timeout on each individual
// request it sends. base is the RoundTripper that actually sends a request
// once the limiter releases it; nil selects http.DefaultTransport, the same
// zero-value behavior http.Client.Transport itself has.
func NewRateLimitedTransport(base http.RoundTripper, rate float64, timeout time.Duration) *RateLimitedTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &RateLimitedTransport{Base: base, Timeout: timeout, limiter: newHostLimiter(rate)}
}

func (t *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.wait(req.Context(), req.URL.Host); err != nil {
		return nil, err
	}

	// The timeout context is created only now, after the limiter has
	// released this request, so it gets the full Timeout budget regardless
	// of how long the wait above took.
	ctx, cancel := context.WithTimeout(req.Context(), t.Timeout)
	resp, err := t.Base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	// cancel can't run here: the caller hasn't read the response body yet,
	// and canceling now would abort that read. It's deferred to the body's
	// Close instead, via cancelOnCloseBody below.
	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnCloseBody releases a RateLimitedTransport request's per-request
// timeout context once its response body is closed, rather than leaking it
// until the timeout itself elapses.
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}
