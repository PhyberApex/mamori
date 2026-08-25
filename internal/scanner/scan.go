package scanner

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// Scan fans the URLs out to a fixed pool of worker goroutines. A failed
// target becomes an error finding instead of aborting the scan, so every
// target is accounted for in the report. headers, if non-nil, is applied to
// every outgoing request (e.g. for endpoints that require auth).
func Scan(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, urls []string, workers int, headers http.Header) []Finding {
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
				perTarget[i] = scanTarget(ctx, client, checkers, bodyCheckers, urls[i], headers)
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
func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, url string, reqHeaders http.Header) []Finding {
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

	findings := append(RunAll(checkers, respHeaders), bodyFindings...)
	for i := range findings {
		findings[i].URL = url
	}
	return findings
}

func fetchHeaders(ctx context.Context, client *http.Client, url string, reqHeaders http.Header) (http.Header, error) {
	headers, status, err := doRequest(ctx, client, http.MethodHead, url, reqHeaders)
	if err != nil {
		return nil, err
	}
	if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		headers, _, err = doRequest(ctx, client, http.MethodGet, url, reqHeaders)
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

func doRequest(ctx context.Context, client *http.Client, method, url string, reqHeaders http.Header) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	applyHeaders(req, reqHeaders)
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
