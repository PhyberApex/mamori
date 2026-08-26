package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Scan fans the URLs out to a fixed pool of worker goroutines. A failed
// target becomes an error finding instead of aborting the scan, so every
// target is accounted for in the report. headers, if non-nil, is applied to
// every outgoing request (e.g. for endpoints that require auth).
func Scan(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, pathCheckers []PathChecker, urls []string, workers int, headers http.Header) []Finding {
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
				perTarget[i] = scanTarget(ctx, client, checkers, bodyCheckers, pathCheckers, urls[i], headers)
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
// same as before body checks existed.
func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, pathCheckers []PathChecker, url string, reqHeaders http.Header) []Finding {
	var respHeaders http.Header
	var bodyFindings []Finding
	var err error

	if len(bodyCheckers) == 0 {
		respHeaders, err = fetchHeaders(ctx, client, url, reqHeaders)
	} else {
		var body []byte
		respHeaders, body, err = fetchBody(ctx, client, url, reqHeaders)
		if err == nil {
			bodyFindings = RunAllBody(bodyCheckers, body, url)
		}
	}
	if err != nil {
		return []Finding{{URL: url, Status: StatusError, Message: err.Error()}}
	}

	plain, originBased := splitOriginProbers(checkers)
	findings := append(RunAll(plain, respHeaders), bodyFindings...)

	// Only pay for the extra request when a configured Checker actually
	// needs it. A probe failure is skipped rather than turned into an error
	// finding: the plain request above already succeeded, so one Checker's
	// extra round trip failing shouldn't blank out everything else this
	// target reported.
	if len(originBased) > 0 {
		if probeHeaders, err := fetchOriginProbeHeaders(ctx, client, url, reqHeaders); err == nil {
			findings = append(findings, RunAll(originBased, probeHeaders)...)
		}
	}

	// Only pay for the exposure-check requests when at least one PathChecker
	// is configured, same opt-in-cost pattern as bodyCheckers/originBased
	// above.
	if len(pathCheckers) > 0 {
		findings = append(findings, scanExposurePaths(ctx, client, pathCheckers, url, reqHeaders)...)
	}

	for i := range findings {
		findings[i].URL = url
	}
	return findings
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
	_, status, err := doRequest(ctx, client, http.MethodGet, target, reqHeaders, "")
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

func fetchHeaders(ctx context.Context, client *http.Client, url string, reqHeaders http.Header) (http.Header, error) {
	return fetchHeadersWithOrigin(ctx, client, url, reqHeaders, "")
}

// fetchOriginProbeHeaders issues the extra request OriginProber checkers
// need: identical to fetchHeaders, but carrying a synthetic cross-origin
// Origin header so a CORS-misconfigured server reveals itself in the
// response.
func fetchOriginProbeHeaders(ctx context.Context, client *http.Client, url string, reqHeaders http.Header) (http.Header, error) {
	return fetchHeadersWithOrigin(ctx, client, url, reqHeaders, CORSProbeOrigin)
}

func fetchHeadersWithOrigin(ctx context.Context, client *http.Client, url string, reqHeaders http.Header, origin string) (http.Header, error) {
	headers, status, err := doRequest(ctx, client, http.MethodHead, url, reqHeaders, origin)
	if err != nil {
		return nil, err
	}
	if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		headers, _, err = doRequest(ctx, client, http.MethodGet, url, reqHeaders, origin)
		if err != nil {
			return nil, err
		}
	}
	return headers, nil
}

// maxBodyBytes caps how much of a response body fetchBody will buffer, so a
// hostile or misconfigured target can't exhaust memory by returning an
// unbounded body. Body checkers only look at the head of the document
// (script/link tags), so a truncated body still yields usable findings.
const maxBodyBytes = 10 * 1024 * 1024 // 10 MiB

// fetchBody always issues a GET, since body checkers need the body itself
// and there's no cheaper request that would provide it.
func fetchBody(ctx context.Context, client *http.Client, url string, reqHeaders http.Header) (http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	applyHeaders(req, reqHeaders)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, body, nil
}

func doRequest(ctx context.Context, client *http.Client, method, url string, reqHeaders http.Header, origin string) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	applyHeaders(req, reqHeaders)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the body so the underlying TCP connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header, resp.StatusCode, nil
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
		req.Header.Set(k, v[0])
	}
}
