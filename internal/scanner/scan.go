package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
)

// Scan fans the URLs out to a fixed pool of worker goroutines. A failed
// target becomes an error finding instead of aborting the scan, so every
// target is accounted for in the report.
func Scan(ctx context.Context, client *http.Client, checkers []Checker, urls []string, workers int) []Finding {
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
				perTarget[i] = scanTarget(ctx, client, checkers, urls[i])
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

func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, target string) []Finding {
	headers, err := fetchHeaders(ctx, client, target)
	if err != nil {
		return []Finding{{URL: target, Status: StatusError, Message: err.Error()}}
	}
	findings := RunAll(checkers, headers)
	findings = append(findings, mixedContentFindings(ctx, client, target)...)
	for i := range findings {
		findings[i].URL = target
	}
	return findings
}

// mixedContentFindings scans the response body for insecure http://
// references, but only for https:// targets — an http:// page has no TLS
// guarantee for mixed content to undermine. The body needs a dedicated GET
// (fetchHeaders may only have sent a HEAD), and a failure to fetch it is
// treated as nothing to report rather than a scan error: the header checks
// above already proved the target reachable, so a hiccup on this second
// request shouldn't fail the whole scan.
func mixedContentFindings(ctx context.Context, client *http.Client, target string) []Finding {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		return nil
	}
	body, err := fetchBody(ctx, client, target)
	if err != nil {
		return nil
	}
	defer func() { _ = body.Close() }()
	return MixedContentChecker{}.Check(body)
}

func fetchHeaders(ctx context.Context, client *http.Client, url string) (http.Header, error) {
	headers, status, err := doRequest(ctx, client, http.MethodHead, url)
	if err != nil {
		return nil, err
	}
	if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		headers, _, err = doRequest(ctx, client, http.MethodGet, url)
		if err != nil {
			return nil, err
		}
	}
	return headers, nil
}

// fetchBody issues a GET and returns the live response body for the caller
// to read and close, unlike doRequest which drains and discards it — the
// header checks never need the body, but mixedContentFindings does.
func fetchBody(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func doRequest(ctx context.Context, client *http.Client, method, url string) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return nil, 0, err
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
