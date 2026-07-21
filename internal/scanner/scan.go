package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func Scan(ctx context.Context, client *http.Client, checkers []Checker, urls []string) ([]Finding, error) {
	var findings []Finding
	for _, url := range urls {
		headers, err := fetchHeaders(ctx, client, url)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", url, err)
		}
		for _, f := range RunAll(checkers, headers) {
			f.URL = url
			findings = append(findings, f)
		}
	}
	return findings, nil
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
