package scanner

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ScanOption configures optional Scan behavior without widening its
// positional signature.
type ScanOption func(*scanOptions)

type scanOptions struct {
	tlsVersionProbe *TLSVersionProbe
}

// WithTLSVersionProbe enables the opt-in TLS legacy-protocol probe.
func WithTLSVersionProbe(p *TLSVersionProbe) ScanOption {
	return func(o *scanOptions) { o.tlsVersionProbe = p }
}

// Scan fans the URLs out to a fixed pool of worker goroutines. A failed
// target becomes an error finding instead of aborting the scan, so every
// target is accounted for in the report. headers, if non-nil, is applied to
// every outgoing request (e.g. for endpoints that require auth).
func Scan(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, pathCheckers []PathChecker, tlsCheckers []TLSChecker, urls []string, workers int, headers http.Header, opts ...ScanOption) []Finding {
	var so scanOptions
	for _, o := range opts {
		o(&so)
	}
	jobs := make(chan int)
	// Each worker writes only to its own job's index, so the slice needs no
	// mutex: distinct goroutines never touch the same element, and wg.Wait()
	// is the synchronisation point that makes the writes visible here.
	perTarget := make([][]Finding, len(urls))

	var wg sync.WaitGroup
	// Floor at one worker so a bad caller can't create a pool of zero
	// goroutines, which would deadlock the unbuffered jobs channel below.
	for range min(max(workers, 1), len(urls)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ranging over a channel keeps receiving until it is closed,
			// which is how each worker knows there is no more work.
			for i := range jobs {
				perTarget[i] = scanTarget(ctx, client, checkers, bodyCheckers, pathCheckers, tlsCheckers, so.tlsVersionProbe, urls[i], headers)
			}
		}()
	}
	for i := range urls {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// Reassembling by index keeps the report in input order even though
	// workers finish in arbitrary order.
	var findings []Finding
	for _, fs := range perTarget {
		findings = append(findings, fs...)
	}
	return findings
}

// scanTarget only pays for a body download when a BodyChecker actually needs
// one: with none configured it keeps the HEAD-preferring fetchHeaders path,
// same as before body checks existed. The targetURL parameter is the URL the
// user typed and is what every returned Finding is keyed by (see the loop at
// the bottom); it is deliberately not passed to RunAll/RunAllBody, which
// instead get the final, post-redirect URL each response actually came from.
func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, pathCheckers []PathChecker, tlsCheckers []TLSChecker, tlsVersionProbe *TLSVersionProbe, targetURL string, reqHeaders http.Header) []Finding {
	var respHeaders http.Header
	var respURL *url.URL
	var respStatus int
	var respTLS *tls.ConnectionState
	var bodyFindings []Finding
	var err error

	if len(bodyCheckers) == 0 {
		respHeaders, respURL, respStatus, respTLS, err = fetchHeaders(ctx, client, targetURL, reqHeaders)
	} else {
		var body []byte
		respHeaders, respURL, respStatus, respTLS, body, err = fetchBody(ctx, client, targetURL, reqHeaders)
		if err == nil {
			bodyFindings = RunAllBody(bodyCheckers, body, respHeaders, respURL)
		}
	}
	if err != nil {
		// ctx (not the request's own derived context — see
		// RateLimitedTransport) is only ever canceled by the signal handler
		// run() installs around the scan phase, so its being done here means
		// this request was aborted by an interrupt rather than failing on
		// its own merits; that gets the literal "scan interrupted" message
		// instead of the request error's own text.
		if ctx.Err() != nil {
			return []Finding{{URL: targetURL, Status: StatusError, Message: "scan interrupted"}}
		}
		return []Finding{{URL: targetURL, Status: StatusError, Message: err.Error()}}
	}

	plain, originBased := splitOriginProbers(checkers)
	findings := append(RunAll(plain, respHeaders, respURL), bodyFindings...)
	findings = append(findings, RunAllTLS(tlsCheckers, respTLS, respURL)...)
	setFinalURL(findings, targetURL, respURL)
	setStatusCode(findings, respStatus)

	// The opt-in legacy-protocol probe issues its own handshakes (ADR-0005);
	// it judges the same host the scan request landed on, so its Findings
	// carry the same Final URL and status as that response.
	if respTLS != nil {
		probeFindings := tlsVersionProbe.Probe(ctx, respURL)
		setFinalURL(probeFindings, targetURL, respURL)
		setStatusCode(probeFindings, respStatus)
		findings = append(findings, probeFindings...)
	}

	// Only pay for the extra request when a configured Checker actually
	// needs it. A probe failure is skipped rather than turned into an error
	// finding: the plain request above already succeeded, so one Checker's
	// extra round trip failing shouldn't blank out everything else this
	// target reported.
	if len(originBased) > 0 {
		if probeHeaders, probeURL, probeStatus, err := fetchOriginProbeHeaders(ctx, client, targetURL, reqHeaders); err == nil {
			originFindings := RunAll(originBased, probeHeaders, probeURL)
			setFinalURL(originFindings, targetURL, probeURL)
			setStatusCode(originFindings, probeStatus)
			findings = append(findings, originFindings...)
		}
	}

	// Only pay for the exposure-check requests when at least one PathChecker
	// is configured, same opt-in-cost pattern as bodyCheckers/originBased
	// above.
	if len(pathCheckers) > 0 {
		findings = append(findings, scanExposurePaths(ctx, client, pathCheckers, targetURL, reqHeaders)...)
	}

	for i := range findings {
		findings[i].URL = targetURL
	}
	return appendInterruptedOnce(ctx, findings, targetURL)
}

// appendInterruptedOnce adds the "scan interrupted" error Finding when ctx
// was canceled and findings doesn't already carry one. The CORS probe and the
// per-path exposure probes skip a failed request silently, so without this a
// target interrupted mid-probe would report its real Findings with no marker
// that part of it was never judged. Non-cancellation probe failures stay
// skipped.
func appendInterruptedOnce(ctx context.Context, findings []Finding, targetURL string) []Finding {
	if ctx.Err() == nil {
		return findings
	}
	for _, f := range findings {
		if f.Status == StatusError && f.Message == "scan interrupted" {
			return findings
		}
	}
	return append(findings, Finding{URL: targetURL, Status: StatusError, Message: "scan interrupted"})
}

// scanExposurePaths runs the sensitive-path exposure check for one target.
// It first issues a probe to a randomized, deliberately-nonexistent path at
// the target's origin: if that doesn't come back 404, the target is a
// soft-404/catch-all server (or the probe itself failed), which would make
// every configured path below look exposed regardless of whether it
// actually is — so this returns exactly one StatusError Finding noting the
// check was skipped, and probes none of the configured paths. Otherwise
// every configured path is probed concurrently, root-relative to the
// target's origin regardless of any path component in targetURL itself —
// mamori issues no other requests per target for this check, so there's no
// staggering to do.
func scanExposurePaths(ctx context.Context, client *http.Client, pathCheckers []PathChecker, targetURL string, reqHeaders http.Header) []Finding {
	origin, err := targetOrigin(targetURL)
	if err != nil {
		return nil
	}

	baselineStatus, err := probePathStatus(ctx, client, origin, randomExposureProbePath(), reqHeaders)
	if err != nil || baselineStatus != http.StatusNotFound {
		// Same interrupt-vs-genuine-failure distinction as scanTarget's own
		// error branch: a canceled ctx here means the baseline probe was
		// aborted by an interrupt, not that the target looked like a
		// soft-404 catch-all, so it must get the literal "scan interrupted"
		// message instead of the misleading skipped-check one.
		if ctx.Err() != nil {
			return []Finding{{Status: StatusError, Message: "scan interrupted"}}
		}
		return []Finding{{
			Status:  StatusError,
			Message: "sensitive-path exposure check skipped: target did not return 404 for a random nonexistent path, so its responses can't be trusted to tell an exposed path from a missing one",
		}}
	}

	var mu sync.Mutex
	var findings []Finding
	var wg sync.WaitGroup
	for _, pc := range pathCheckers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A single path's probe failing (as opposed to the baseline
			// probe above) is skipped rather than turned into a Finding,
			// the same "don't blank out everything else on one extra
			// request failing" treatment fetchOriginProbeHeaders gets.
			status, err := probePathStatus(ctx, client, origin, pc.Path(), reqHeaders)
			if err != nil {
				return
			}
			fs := pc.CheckStatus(status)
			if len(fs) == 0 {
				return
			}
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return findings
}

// setFinalURL stamps fs's FinalURL with respURL's string form, but only when
// it differs from targetURL (the typed target) — see the Final URL glossary
// entry in CONTEXT.md. Left unset (the zero value) when the two match, so a
// non-redirecting target's Findings serialize identically to before this
// field existed.
func setFinalURL(fs []Finding, targetURL string, respURL *url.URL) {
	final := respURL.String()
	if final == targetURL {
		return
	}
	// A typed target that net/url would re-serialize (uppercase scheme,
	// unescaped space) is not a redirect: compare against its canonical form.
	if parsed, err := url.Parse(targetURL); err == nil && final == parsed.String() {
		return
	}
	for i := range fs {
		fs[i].FinalURL = final
	}
}

// setStatusCode stamps fs's StatusCode with status, but only when status is
// not 2xx — see the Final Status glossary entry in CONTEXT.md. Left unset
// (the zero value) when the response was 2xx, so a target whose judged
// response is 2xx serializes identically to before this field existed.
func setStatusCode(fs []Finding, status int) {
	if status/100 == 2 {
		return
	}
	for i := range fs {
		fs[i].StatusCode = status
	}
}

// targetOrigin returns targetURL's scheme+host, discarding any path/query:
// exposure paths are always probed root-relative to the origin, never
// relative to whatever path component the target URL itself has.
func targetOrigin(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// probePathStatus issues a GET for path at origin and returns the response
// status code. GET rather than the plain scan's HEAD-then-fallback: some of
// the paths this check probes (e.g. .htpasswd) are handled by servers that
// only recognize GET, and this check only needs a status code, so there's no
// benefit to a second request the way the HEAD/GET fallback avoids one for
// header inspection.
func probePathStatus(ctx context.Context, client *http.Client, origin, path string, reqHeaders http.Header) (int, error) {
	target := origin + "/" + strings.TrimPrefix(path, "/")
	_, _, status, _, err := doRequest(ctx, client, http.MethodGet, target, reqHeaders, "")
	return status, err
}

// randomExposureProbePath returns a root-relative path that's exceedingly
// unlikely to exist on a real target and different on every call, so a
// target can't special-case a fixed probe string to defeat
// scanExposurePaths' baseline reliability check.
func randomExposureProbePath() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand.Read only fails if the OS entropy source is
		// unavailable, in which case the process has bigger problems than
		// this probe. A fixed fallback keeps the baseline check functional
		// (if no longer unguessable) rather than panicking mid-scan.
		return "mamori-exposure-probe-fallback"
	}
	return "mamori-exposure-probe-" + hex.EncodeToString(buf[:])
}

// splitOriginProbers separates checkers that judge the plain scan request
// from OriginProber checkers that need the synthetic-Origin probe response
// instead, so scanTarget only issues the extra request when one is present.
func splitOriginProbers(checkers []Checker) (plain, originBased []Checker) {
	for _, c := range checkers {
		if _, ok := c.(OriginProber); ok {
			originBased = append(originBased, c)
			continue
		}
		plain = append(plain, c)
	}
	return plain, originBased
}

func fetchHeaders(ctx context.Context, client *http.Client, targetURL string, reqHeaders http.Header) (http.Header, *url.URL, int, *tls.ConnectionState, error) {
	return fetchHeadersWithOrigin(ctx, client, targetURL, reqHeaders, "")
}

// fetchOriginProbeHeaders issues the extra request OriginProber checkers
// need: identical to fetchHeaders, but carrying a synthetic cross-origin
// Origin header so a CORS-misconfigured server reveals itself in the
// response.
func fetchOriginProbeHeaders(ctx context.Context, client *http.Client, targetURL string, reqHeaders http.Header) (http.Header, *url.URL, int, error) {
	headers, respURL, status, _, err := fetchHeadersWithOrigin(ctx, client, targetURL, reqHeaders, CORSProbeOrigin)
	return headers, respURL, status, err
}

func fetchHeadersWithOrigin(ctx context.Context, client *http.Client, targetURL string, reqHeaders http.Header, origin string) (http.Header, *url.URL, int, *tls.ConnectionState, error) {
	headers, respURL, status, respTLS, err := doRequest(ctx, client, http.MethodHead, targetURL, reqHeaders, origin)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		headers, respURL, status, respTLS, err = doRequest(ctx, client, http.MethodGet, targetURL, reqHeaders, origin)
		if err != nil {
			return nil, nil, 0, nil, err
		}
	}
	return headers, respURL, status, respTLS, nil
}

// maxBodyBytes caps how much of a response body fetchBody will buffer, so a
// hostile or misconfigured target can't exhaust memory by returning an
// unbounded body. Body checkers only look at the head of the document
// (script/link tags), so a truncated body still yields usable findings.
const maxBodyBytes = 10 * 1024 * 1024 // 10 MiB

// maxDrainBytes caps how much of a response body doRequest reads before
// closing it, since only the status and headers are needed.
const maxDrainBytes = 64 << 10 // 64 KiB

// fetchBody always issues a GET, since body checkers need the body itself
// and there's no cheaper request that would provide it.
func fetchBody(ctx context.Context, client *http.Client, targetURL string, reqHeaders http.Header) (http.Header, *url.URL, int, *tls.ConnectionState, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, nil, 0, nil, nil, err
	}
	applyHeaders(req, reqHeaders)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, 0, nil, nil, err
	}
	return resp.Header, resp.Request.URL, resp.StatusCode, resp.TLS, body, nil
}

func doRequest(ctx context.Context, client *http.Client, method, targetURL string, reqHeaders http.Header, origin string) (http.Header, *url.URL, int, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, http.NoBody)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	applyHeaders(req, reqHeaders)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain a small prefix of the body so the underlying TCP connection can
	// be reused. Anything larger (an exposed backup.zip can be gigabytes) is
	// abandoned: closing the body makes the transport drop the connection,
	// which beats downloading the file just to read a status code.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))

	// resp.Request is not the request we built above — after client.Do
	// follows any redirects, the standard library rewrites it to point at
	// the last request actually sent, so its URL is the final, post-redirect
	// URL the headers we're returning came from. That's the honest URL for a
	// Checker to judge scheme-dependent behavior against, not targetURL.
	// resp.TLS is nil whenever this response arrived over plain HTTP.
	return resp.Header, resp.Request.URL, resp.StatusCode, resp.TLS, nil
}

// applyHeaders sets each of reqHeaders on req, overriding any header of the
// same name Go's http package would otherwise set (e.g. a custom User-Agent),
// same as curl's -H. Only the first value per key is applied: reqHeaders
// only ever holds one, since config.Headers.Set builds it with
// http.Header.Set rather than Add.
func applyHeaders(req *http.Request, reqHeaders http.Header) {
	for k, v := range reqHeaders {
		if len(v) == 0 {
			continue
		}
		// net/http ignores a Host key in req.Header and sends req.Host
		// instead, so -H 'Host: ...' must be applied there to take effect.
		if http.CanonicalHeaderKey(k) == "Host" {
			req.Host = v[0]
			continue
		}
		req.Header.Set(k, v[0])
	}
}
