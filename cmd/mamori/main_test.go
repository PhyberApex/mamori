package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// strongHeaders returns headers that pass every default checker, so a
// server built from this map alone never trips -fail-on at any severity.
func strongHeaders() map[string]string {
	return map[string]string{
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Content-Security-Policy":      "default-src 'self'",
		"Referrer-Policy":              "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy":           "geolocation=()",
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

func TestRunEmitsSarifOutput(t *testing.T) {
	url := headerServer(t, nil) // every header missing

	var buf bytes.Buffer
	if err := run([]string{"-o", "sarif", url}, nil, &buf); err != nil {
		t.Fatalf("run() with -o sarif returned %v, want nil", err)
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("got no SARIF results for a scan with missing headers\noutput:\n%s", buf.String())
	}
}

func TestRunRejectsUnknownOutputFormat(t *testing.T) {
	url := headerServer(t, strongHeaders())
	err := run([]string{"-o", "xml", url}, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a known output format") {
		t.Errorf("run() with -o xml returned %v, want a known-output-format error", err)
	}
}

func TestRunVersionFlagPrintsVersionAndPerformsNoScan(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-version"}, nil, &buf); err != nil {
		t.Fatalf("run() with -version returned %v, want nil", err)
	}
	if got := buf.String(); !strings.Contains(got, version) {
		t.Errorf("run() with -version wrote %q, want it to contain %q", got, version)
	}
}

func TestRunVersionShorthandFlagPrintsVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-v"}, nil, &buf); err != nil {
		t.Fatalf("run() with -v returned %v, want nil", err)
	}
	if got := buf.String(); !strings.Contains(got, version) {
		t.Errorf("run() with -v wrote %q, want it to contain %q", got, version)
	}
}

func TestRunSuppressedFindingDoesNotTripFailOnButStaysInOutput(t *testing.T) {
	url := headerServer(t, nil) // every header missing, including high severity

	configPath := filepath.Join(t.TempDir(), "mamori.yaml")
	config := "suppressions:\n" +
		"  - host: " + url + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	var buf bytes.Buffer
	err := run([]string{"-config", configPath, "-fail-on", "high", "-o", "json", url}, nil, &buf)
	if err != nil {
		t.Errorf("run() with every finding suppressed returned %v, want nil", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("run() wrote no findings, want suppressed findings still reported\noutput:\n%s", buf.String())
	}
	for _, line := range lines {
		var f map[string]any
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line is not valid JSON: %v\nline: %s", err, line)
		}
		if f["suppressed"] != true {
			t.Errorf("finding %v suppressed = %v, want true", f, f["suppressed"])
		}
		if f["status"] != "missing" {
			t.Errorf("finding %v status = %v, want unchanged %q", f, f["status"], "missing")
		}
	}
}

func TestRunDefaultDoesNotProbeExposedPaths(t *testing.T) {
	var probed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			probed = true
		}
	}))
	t.Cleanup(srv.Close)

	if err := run([]string{srv.URL}, nil, io.Discard); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}
	if probed {
		t.Error("run() probed /.git/config with -check-exposed-paths unset, want the category off by default")
	}
}

func TestRunCheckExposedPathsFlagFindsExposedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	if err := run([]string{"-check-exposed-paths", "-o", "json", srv.URL}, nil, &buf); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}

	var sawExposed bool
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var f map[string]any
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line is not valid JSON: %v\nline: %s", err, line)
		}
		if f["status"] == "exposed" && f["header"] == ".env" {
			sawExposed = true
		}
	}
	if !sawExposed {
		t.Errorf("run() with -check-exposed-paths did not report .env as exposed\noutput:\n%s", buf.String())
	}
}

func TestRunFailOnGatesOnExposedFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	err := run([]string{"-check-exposed-paths", "-fail-on", "high", srv.URL}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with an exposed .env and -fail-on high returned %v, want errFailThreshold", err)
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
