package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// maxBodyBytes caps how much of a response body a BodyChecker ever reads.
// Mixed-content references live in early markup (head/early body), so a few
// megabytes is generous — the cap exists to keep an arbitrary scan target
// from forcing an unbounded amount of memory per request.
const maxBodyBytes = 5 * 1024 * 1024

// Scan fans the URLs out to a fixed pool of worker goroutines. A failed
// target becomes an error finding instead of aborting the scan, so every
// target is accounted for in the report.
func Scan(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, urls []string, workers int) []Finding {
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
				perTarget[i] = scanTarget(ctx, client, checkers, bodyCheckers, urls[i])
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

func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, target string) []Finding {
	headers, fallback, err := fetchHeaders(ctx, client, target)
	if err != nil {
		return []Finding{{URL: target, Status: StatusError, Message: err.Error()}}
	}
	findings := RunAll(checkers, headers)
	findings = append(findings, bodyFindings(ctx, client, target, fallback, bodyCheckers)...)
	for i := range findings {
		findings[i].URL = target
	}
	return findings
}

// bodyFindings runs bodyCheckers against an https:// target's response
// body — an http:// target has no TLS guarantee for mixed content to
// undermine, so it's skipped entirely, and a target with no BodyCheckers
// configured never triggers the extra request at all.
//
// fallback is the live response fetchHeaders already obtained by falling
// back to GET (nil when HEAD succeeded); reusing it avoids a second GET to
// the same target. A body-fetch failure is reported as its own StatusError
// finding rather than silently skipped, so "zero findings" always means
// "checked and clean," never "the check didn't run."
func bodyFindings(ctx context.Context, client *http.Client, target string, fallback *http.Response, bodyCheckers []BodyChecker) []Finding {
	if fallback != nil {
		defer func() { _ = fallback.Body.Close() }()
	}
	if len(bodyCheckers) == 0 {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		return nil
	}

	resp := fallback
	if resp == nil {
		resp, err = sendRequest(ctx, client, http.MethodGet, target)
		if err != nil {
			return []Finding{{Header: "Mixed Content", Status: StatusError, Message: err.Error()}}
		}
		defer func() { _ = resp.Body.Close() }()
	}
	// A non-2xx response (error page, bot-challenge interstitial) or a
	// non-HTML body (JSON API, binary download) isn't the page mamori was
	// asked to check, so scanning it would misattribute someone else's
	// markup as this target's mixed content.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		return nil
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return []Finding{{Header: "Mixed Content", Status: StatusError, Message: err.Error()}}
	}
	var findings []Finding
	for _, c := range bodyCheckers {
		findings = append(findings, c.Check(bytes.NewReader(raw))...)
	}
	return findings
}

// fetchHeaders issues a HEAD, falling back to GET if the server rejects it.
// The returned *http.Response is non-nil only when that GET fallback ran,
// with its body still open for bodyFindings to reuse instead of paying for
// a second GET to the same target; the caller must close it when non-nil.
func fetchHeaders(ctx context.Context, client *http.Client, target string) (http.Header, *http.Response, error) {
	headers, status, err := doRequest(ctx, client, http.MethodHead, target)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusMethodNotAllowed && status != http.StatusNotImplemented {
		return headers, nil, nil
	}
	resp, err := sendRequest(ctx, client, http.MethodGet, target)
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, resp, nil
}

func doRequest(ctx context.Context, client *http.Client, method, target string) (http.Header, int, error) {
	resp, err := sendRequest(ctx, client, method, target)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the body so the underlying TCP connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header, resp.StatusCode, nil
}

func sendRequest(ctx context.Context, client *http.Client, method, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
