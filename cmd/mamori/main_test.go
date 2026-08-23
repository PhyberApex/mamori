package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// strongHeaders returns headers that pass every default checker, so a
// server built from this map alone never trips -fail-on at any severity.
func strongHeaders() map[string]string {
	return map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
}

func headerServer(t *testing.T, headers map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range headers {
			w.Header().Set(name, value)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRunDefaultNeverFailsOnFindings(t *testing.T) {
	url := headerServer(t, nil) // every header missing, including high severity
	if err := run([]string{url}, nil, io.Discard); err != nil {
		t.Errorf("run() with -fail-on unset returned %v, want nil", err)
	}
}

func TestRunDefaultNeverFailsOnScanError(t *testing.T) {
	// Nothing listens here, so the scan itself fails and produces a
	// StatusError finding. Even that must not fail the run when -fail-on
	// is unset, since "none" has to mean "never fail" unconditionally.
	if err := run([]string{"http://127.0.0.1:1"}, nil, io.Discard); err != nil {
		t.Errorf("run() with -fail-on unset returned %v, want nil for a scan error", err)
	}
}

func TestRunFailOnMediumFailsOnMissingFindings(t *testing.T) {
	url := headerServer(t, nil)
	err := run([]string{"-fail-on", "medium", url}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with -fail-on medium returned %v, want errFailThreshold", err)
	}
}

func TestRunFailOnHighIgnoresMediumWeakFinding(t *testing.T) {
	headers := strongHeaders()
	// ALLOW-FROM is not DENY/SAMEORIGIN, so this is StatusWeak at
	// SeverityMedium — below the -fail-on high threshold.
	headers["X-Frame-Options"] = "ALLOW-FROM https://example.com"
	url := headerServer(t, headers)

	if err := run([]string{"-fail-on", "high", url}, nil, io.Discard); err != nil {
		t.Errorf("run() with -fail-on high returned %v, want nil for a medium-severity weak finding", err)
	}
}

func TestRunFailOnHighFailsOnHighSeverityMissingFinding(t *testing.T) {
	headers := strongHeaders()
	delete(headers, "Content-Security-Policy") // high severity, missing
	url := headerServer(t, headers)

	err := run([]string{"-fail-on", "high", url}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with -fail-on high returned %v, want errFailThreshold", err)
	}
}

func TestRunFailOnAlwaysFailsOnScanError(t *testing.T) {
	// Nothing listens here, so the scan itself fails and produces a
	// StatusError finding, which must fail regardless of severity.
	err := run([]string{"-fail-on", "high", "http://127.0.0.1:1"}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with an unreachable target returned %v, want errFailThreshold", err)
	}
}

func TestRunFailOnNoneMatchesDefault(t *testing.T) {
	url := headerServer(t, nil)
	if err := run([]string{"-fail-on", "none", url}, nil, io.Discard); err != nil {
		t.Errorf("run() with -fail-on none returned %v, want nil", err)
	}
}

func TestRunRejectsInvalidFailOnFlag(t *testing.T) {
	url := headerServer(t, strongHeaders())
	err := run([]string{"-fail-on", "critical", url}, nil, io.Discard)
	if err == nil {
		t.Fatal("run() with -fail-on critical returned nil error, want error")
	}
	if errors.Is(err, errFailThreshold) {
		t.Error("run() with -fail-on critical returned errFailThreshold, want a flag-parsing error")
	}
}

func TestRunFailOnEnvVar(t *testing.T) {
	url := headerServer(t, nil)
	t.Setenv("MAMORI_FAIL_ON", "low")

	err := run([]string{url}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with MAMORI_FAIL_ON=low returned %v, want errFailThreshold", err)
	}
}

func TestRunFailOnFlagOverridesEnvVar(t *testing.T) {
	url := headerServer(t, nil)
	t.Setenv("MAMORI_FAIL_ON", "low")

	err := run([]string{"-fail-on", "none", url}, nil, io.Discard)
	if err != nil {
		t.Errorf("run() with -fail-on none overriding MAMORI_FAIL_ON=low returned %v, want nil", err)
	}
}
