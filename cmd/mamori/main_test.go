package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// writeTransportSuppressionConfig writes a config file suppressing the
// Transport header, the documented opt-out for a deliberately plain-HTTP
// target, and returns its path.
func writeTransportSuppressionConfig(t *testing.T) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "mamori.yaml")
	config := "suppressions:\n  - header: Transport\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	return configPath
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

	// headerServer is plain HTTP, so TransportChecker's own high-severity
	// insecure Finding would otherwise trip -fail-on high regardless of the
	// medium-severity finding this test means to isolate; suppressing it is
	// the documented opt-out for a deliberately plain-HTTP target.
	configPath := writeTransportSuppressionConfig(t)

	if err := run([]string{"-config", configPath, "-fail-on", "high", url}, nil, io.Discard); err != nil {
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
		// Every header this server left unset reports missing except
		// Transport, which always reports a Finding regardless of headers —
		// insecure here, since the server is plain HTTP.
		wantStatus := "missing"
		if f["header"] == "Transport" {
			wantStatus = "insecure"
		}
		if f["status"] != wantStatus {
			t.Errorf("finding %v status = %v, want unchanged %q", f, f["status"], wantStatus)
		}
	}
}

func TestRunTerminalOutputToNonTerminalWriterOmitsAnsiEscapes(t *testing.T) {
	url := headerServer(t, nil) // every header missing, including high severity

	var buf bytes.Buffer
	if err := run([]string{url}, nil, &buf); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}

	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("run() wrote an ANSI escape sequence to a non-terminal writer\noutput:\n%q", buf.String())
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

func TestRunFailOnGatesOnUnsuppressedTransportInsecureFinding(t *testing.T) {
	url := headerServer(t, strongHeaders()) // plain HTTP: Transport is insecure regardless of headers

	err := run([]string{"-fail-on", "high", url}, nil, io.Discard)
	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with a plain-HTTP target and -fail-on high returned %v, want errFailThreshold", err)
	}
}

func TestRunTransportSuppressionPreventsFailOn(t *testing.T) {
	url := headerServer(t, strongHeaders()) // plain HTTP: Transport is insecure regardless of headers

	configPath := writeTransportSuppressionConfig(t)

	err := run([]string{"-config", configPath, "-fail-on", "high", url}, nil, io.Discard)
	if err != nil {
		t.Errorf("run() with a suppressed Transport finding returned %v, want nil", err)
	}
}

func TestRunExpiredSuppressionNoLongerPreventsFailOnAndWarnsOnStderr(t *testing.T) {
	url := headerServer(t, strongHeaders()) // plain HTTP: Transport is insecure regardless of headers

	configPath := filepath.Join(t.TempDir(), "mamori.yaml")
	config := "suppressions:\n" +
		"  - header: Transport\n" +
		"    expires: 2000-01-01\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("creating pipe: %v", pipeErr)
	}
	origStderr := os.Stderr
	os.Stderr = w
	err := run([]string{"-config", configPath, "-fail-on", "high", url}, nil, io.Discard)
	os.Stderr = origStderr
	w.Close()
	captured, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("reading captured stderr: %v", readErr)
	}

	if !errors.Is(err, errFailThreshold) {
		t.Errorf("run() with an expired Transport suppression returned %v, want errFailThreshold", err)
	}
	if !strings.Contains(string(captured), "Transport") {
		t.Errorf("stderr = %q, want it to name the expired Transport suppression", string(captured))
	}
}

func TestRunPreScanHookFailureAbortsBeforeAnyRequest(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	err := run([]string{"-pre-scan-hook", "exit 1", srv.URL}, nil, &buf)
	if err == nil {
		t.Fatal("run() with a failing -pre-scan-hook returned nil error, want error")
	}
	if !strings.Contains(err.Error(), "pre-scan hook") {
		t.Errorf("run() error = %q, want it to name the pre-scan hook", err.Error())
	}
	if !errors.Is(err, errHookFailed) {
		t.Errorf("run() error = %v, want errHookFailed", err)
	}
	if requests != 0 {
		t.Errorf("run() made %d requests to the target, want 0: a failing pre-scan hook must abort before any HTTP request", requests)
	}
	if buf.Len() != 0 {
		t.Errorf("run() wrote %q, want no output when the pre-scan hook aborts the scan", buf.String())
	}
}

func TestRunPreScanHookReceivesResolvedTargets(t *testing.T) {
	url := headerServer(t, strongHeaders())
	outPath := filepath.Join(t.TempDir(), "targets.txt")

	err := run([]string{"-pre-scan-hook", "printenv MAMORI_HOOK_TARGETS > " + outPath, url}, nil, io.Discard)
	if err != nil {
		t.Fatalf("run() returned %v, want nil", err)
	}
	//nolint:gosec // G304 false positive: outPath is a t.TempDir() path this test itself constructed, not attacker-controlled input
	got, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("reading hook output: %v", readErr)
	}
	if strings.TrimSpace(string(got)) != url {
		t.Errorf("MAMORI_HOOK_TARGETS = %q, want %q", strings.TrimSpace(string(got)), url)
	}
}

func TestRunPreScanHookReceivesPrePhase(t *testing.T) {
	url := headerServer(t, strongHeaders())
	err := run([]string{"-pre-scan-hook", `test "$MAMORI_HOOK_PHASE" = "pre"`, url}, nil, io.Discard)
	if err != nil {
		t.Errorf("run() with a pre-scan hook checking MAMORI_HOOK_PHASE returned %v, want nil", err)
	}
}

func TestRunPostScanHookRunsAfterScanEvenOnScanError(t *testing.T) {
	// Nothing listens here, so the scan itself produces a StatusError
	// finding; the post-scan hook must still run.
	outPath := filepath.Join(t.TempDir(), "ran.txt")
	err := run([]string{"-post-scan-hook", "touch " + outPath, "http://127.0.0.1:1"}, nil, io.Discard)
	if err != nil {
		t.Errorf("run() returned %v, want nil", err)
	}
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Errorf("post-scan hook did not run after a scan error: %v", statErr)
	}
}

func TestRunPostScanHookFailureStillReportsFindingsButExitsNonZero(t *testing.T) {
	url := headerServer(t, nil) // every header missing

	var buf bytes.Buffer
	err := run([]string{"-post-scan-hook", "exit 1", "-o", "json", url}, nil, &buf)
	if err == nil {
		t.Fatal("run() with a failing -post-scan-hook returned nil error, want error")
	}
	if errors.Is(err, errFailThreshold) {
		t.Error("run() with a failing -post-scan-hook returned errFailThreshold, want a distinct hook error")
	}
	if !errors.Is(err, errHookFailed) {
		t.Errorf("run() error = %v, want errHookFailed", err)
	}
	if !strings.Contains(err.Error(), "post-scan hook") {
		t.Errorf("run() error = %q, want it to name the post-scan hook", err.Error())
	}
	if buf.Len() == 0 {
		t.Error("run() wrote no findings, want the scan's findings still reported despite the post-scan hook failing")
	}
}

func TestRunPostScanHookFailureTakesPriorityWhenFailOnAlsoTrips(t *testing.T) {
	url := headerServer(t, nil) // every header missing, including high severity

	var buf bytes.Buffer
	err := run([]string{"-post-scan-hook", "exit 1", "-fail-on", "high", "-o", "json", url}, nil, &buf)
	if err == nil {
		t.Fatal("run() with a failing -post-scan-hook and a tripped -fail-on returned nil error, want error")
	}
	// The report already shows which findings crossed the -fail-on
	// threshold, and the exit code is non-zero either way, so the hook
	// failure — the more unusual, actionable problem — is what's surfaced,
	// rather than being silently replaced by the routine fail-on error.
	if !strings.Contains(err.Error(), "post-scan hook") {
		t.Errorf("run() error = %q, want it to name the post-scan hook even though -fail-on also tripped", err.Error())
	}
	if !errors.Is(err, errHookFailed) {
		t.Errorf("run() error = %v, want errHookFailed so main() exits 3, not 1, when both trip", err)
	}
	if buf.Len() == 0 {
		t.Error("run() wrote no findings, want the scan's findings still reported")
	}
}

func TestRunPostScanHookNotRunWhenPreScanHookFails(t *testing.T) {
	url := headerServer(t, strongHeaders())
	outPath := filepath.Join(t.TempDir(), "ran.txt")

	err := run([]string{
		"-pre-scan-hook", "exit 1",
		"-post-scan-hook", "touch " + outPath,
		url,
	}, nil, io.Discard)
	if err == nil {
		t.Fatal("run() with a failing -pre-scan-hook returned nil error, want error")
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Error("post-scan hook ran despite the pre-scan hook failing, want it skipped")
	}
}

func TestRunNoHooksConfiguredSpawnsNoSubprocess(t *testing.T) {
	url := headerServer(t, strongHeaders())
	if err := run([]string{url}, nil, io.Discard); err != nil {
		t.Errorf("run() with no hooks configured returned %v, want nil", err)
	}
}

func TestRunHookTimeoutFlagBoundsPreScanHook(t *testing.T) {
	url := headerServer(t, strongHeaders())
	err := run([]string{"-pre-scan-hook", "sleep 5", "-hook-timeout", "20ms", url}, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("run() error = %v, want a timeout error", err)
	}
}

func TestNoColorSetTrueWhenPresentRegardlessOfValue(t *testing.T) {
	for _, value := range []string{"", "0", "1", "true", "false"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("NO_COLOR", value)
			if !noColorSet() {
				t.Errorf("noColorSet() = false with NO_COLOR=%q, want true", value)
			}
		})
	}
}

func TestNoColorSetFalseWhenUnset(t *testing.T) {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		t.Skip("NO_COLOR is set in the ambient test environment")
	}
	if noColorSet() {
		t.Error("noColorSet() = true with NO_COLOR unset, want false")
	}
}

func TestIsTerminalFalseForRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()

	if isTerminal(f) {
		t.Error("isTerminal() = true for a regular file, want false")
	}
}

func TestIsTerminalFalseForNonFileWriter(t *testing.T) {
	if isTerminal(&bytes.Buffer{}) {
		t.Error("isTerminal() = true for a bytes.Buffer, want false")
	}
}

func TestColorEnabledFalseWhenOutIsNotATerminal(t *testing.T) {
	if colorEnabled(&bytes.Buffer{}) {
		t.Error("colorEnabled() = true for a bytes.Buffer, want false: it is never an interactive terminal")
	}
}

func TestColorEnabledFalseWhenNoColorSetEvenForATerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	t.Setenv("NO_COLOR", "")

	if colorEnabled(f) {
		t.Error("colorEnabled() = true with NO_COLOR set, want false")
	}
}

func TestExitCodeNilIsZero(t *testing.T) {
	if got := exitCode(nil); got != 0 {
		t.Errorf("exitCode(nil) = %d, want 0", got)
	}
}

func TestExitCodeFailThresholdIsOne(t *testing.T) {
	if got := exitCode(errFailThreshold); got != 1 {
		t.Errorf("exitCode(errFailThreshold) = %d, want 1", got)
	}
}

func TestExitCodeGenericErrorIsTwo(t *testing.T) {
	if got := exitCode(errors.New("boom")); got != 2 {
		t.Errorf("exitCode(generic error) = %d, want 2", got)
	}
}

func TestExitCodeHookFailedIsThree(t *testing.T) {
	if got := exitCode(errHookFailed); got != 3 {
		t.Errorf("exitCode(errHookFailed) = %d, want 3", got)
	}
}

func TestExitCodeHookFailedTakesPriorityOverFailThreshold(t *testing.T) {
	// run() never actually returns an error wrapping both sentinels at once
	// (hookErr short-circuits before the -fail-on check), but exitCode must
	// still prefer the Hook bucket if it ever did, matching run()'s own
	// priority.
	err := fmt.Errorf("%w: %w", errHookFailed, errFailThreshold)
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode() = %d, want 3 when both errHookFailed and errFailThreshold are present", got)
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
