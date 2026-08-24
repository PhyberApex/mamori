package scanner

import (
	"context"
	"io"
	"net/http"
	"sync"
)

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

// scanTarget only pays for a body download when a BodyChecker actually needs
// one: with none configured it keeps the HEAD-preferring fetchHeaders path,
// same as before body checks existed.
func scanTarget(ctx context.Context, client *http.Client, checkers []Checker, bodyCheckers []BodyChecker, url string) []Finding {
	var headers http.Header
	var findings []Finding

	if len(bodyCheckers) == 0 {
		h, err := fetchHeaders(ctx, client, url)
		if err != nil {
			return []Finding{{URL: url, Status: StatusError, Message: err.Error()}}
		}
		headers = h
		findings = RunAll(checkers, headers)
	} else {
		h, body, err := fetchBody(ctx, client, url)
		if err != nil {
			return []Finding{{URL: url, Status: StatusError, Message: err.Error()}}
		}
		headers = h
		findings = RunAll(checkers, headers)
		findings = append(findings, RunAllBody(bodyCheckers, body, url)...)
	}

	for i := range findings {
		findings[i].URL = url
	}
	return findings
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

// fetchBody always issues a GET, since body checkers need the body itself
// and there's no cheaper request that would provide it.
func fetchBody(ctx context.Context, client *http.Client, url string) (http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, body, nil
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
