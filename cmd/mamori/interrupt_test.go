package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// blockingServer returns a target URL whose handler blocks the first request
// it receives until the test's cleanup releases it, plus a channel that
// closes once that request has reached the handler — i.e. is in flight, the
// state interrupt handling is meant to catch.
func blockingServer(t *testing.T) (url string, started <-chan struct{}) {
	t.Helper()
	startedCh := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(startedCh)
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv.URL, startedCh
}

// runInterrupted runs run() with args, sending this test process SIGINT once
// started fires (see blockingServer) and draining the resulting signal-send
// error, so each test only has to assert on run()'s own return value. Safe
// only because by construction started never fires before run()'s own
// signal.NotifyContext (installed just before the scan phase) is already
// registered — see blockingServer, whose handler can't be reached before
// that request is actually sent.
func runInterrupted(t *testing.T, started <-chan struct{}, args []string, out io.Writer) error {
	t.Helper()
	sigErr := make(chan error, 1)
	go func() {
		<-started
		sigErr <- syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()

	err := run(args, nil, out)
	if sendErr := <-sigErr; sendErr != nil {
		t.Fatalf("sending SIGINT to self: %v", sendErr)
	}
	return err
}

func TestRunInterruptedMidScanExitsViaErrInterrupted(t *testing.T) {
	url, started := blockingServer(t)

	var buf bytes.Buffer
	err := runInterrupted(t, started, []string{"-o", "json", url}, &buf)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("run() returned %v, want errInterrupted", err)
	}

	var f map[string]any
	line := strings.TrimRight(buf.String(), "\n")
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if f["status"] != "error" || f["message"] != "scan interrupted" {
		t.Errorf("finding = %v, want status \"error\" and message %q", f, "scan interrupted")
	}
}

func TestRunInterruptedPartialReportKeepsCompletedTargetsFindings(t *testing.T) {
	completed := headerServer(t, strongHeaders())
	blocked, started := blockingServer(t)

	var buf bytes.Buffer
	// -workers 1 makes Scan process targets in input order, so completed
	// finishes before blocked's request is even dispatched.
	err := runInterrupted(t, started, []string{"-workers", "1", "-o", "json", completed, blocked}, &buf)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("run() returned %v, want errInterrupted", err)
	}

	var sawInterrupted, sawCompletedReal bool
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var f map[string]any
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line is not valid JSON: %v\nline: %s", err, line)
		}
		if f["url"] == blocked && f["status"] == "error" && f["message"] == "scan interrupted" {
			sawInterrupted = true
		}
		if f["url"] == completed && f["status"] == "pass" {
			sawCompletedReal = true
		}
	}
	if !sawInterrupted {
		t.Errorf("output missing a %q error finding for the interrupted target\noutput:\n%s", "scan interrupted", buf.String())
	}
	if !sawCompletedReal {
		t.Errorf("output missing the already-completed target's real findings\noutput:\n%s", buf.String())
	}
}

func TestRunInterruptedStillRunsPostScanHook(t *testing.T) {
	url, started := blockingServer(t)

	outPath := filepath.Join(t.TempDir(), "ran.txt")
	err := runInterrupted(t, started, []string{"-post-scan-hook", "touch " + outPath, url}, io.Discard)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("run() returned %v, want errInterrupted", err)
	}
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Errorf("post-scan hook did not run after an interrupted scan: %v", statErr)
	}
}

func TestRunInterruptedTakesPriorityOverPostScanHookFailure(t *testing.T) {
	url, started := blockingServer(t)

	err := runInterrupted(t, started, []string{"-post-scan-hook", "exit 1", url}, io.Discard)
	if errors.Is(err, errHookFailed) {
		t.Error("run() returned errHookFailed, want errInterrupted to take priority")
	}
	if !errors.Is(err, errInterrupted) {
		t.Errorf("run() returned %v, want errInterrupted even though the post-scan hook also failed", err)
	}
}

func TestRunInterruptedTakesPriorityOverFailOn(t *testing.T) {
	// The blocked target's own "scan interrupted" finding always trips
	// -fail-on regardless of threshold, so this alone already proves
	// -fail-on would fire here if errInterrupted didn't take priority.
	url, started := blockingServer(t)

	err := runInterrupted(t, started, []string{"-fail-on", "high", url}, io.Discard)
	if errors.Is(err, errFailThreshold) {
		t.Error("run() returned errFailThreshold, want errInterrupted to take priority")
	}
	if !errors.Is(err, errInterrupted) {
		t.Errorf("run() returned %v, want errInterrupted", err)
	}
}

// TestRunSecondSignalDuringPostScanHookKillsProcessImmediately exercises the
// one part of this feature that can't be observed in-process: that default
// OS signal disposition is restored as soon as the first SIGINT is handled,
// so a second SIGINT arriving later (here, while -post-scan-hook is still
// running) kills mamori outright instead of being caught again. That needs
// an actual separate process — sending a real second SIGINT to this test
// binary itself would take the whole suite down with it.
func TestRunSecondSignalDuringPostScanHookKillsProcessImmediately(t *testing.T) {
	ctx := context.Background()
	binPath := filepath.Join(t.TempDir(), "mamori-under-test")
	//nolint:gosec // G204: binPath is a t.TempDir() path this test itself constructed, not attacker-controlled input
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building mamori for the subprocess test: %v\n%s", err, out)
	}

	url, started := blockingServer(t)

	// The hook's own stdout/stderr are routed to mamori's stderr (see
	// runHook), so "hook-started" landing on the subprocess's stderr is a
	// blocking, sleep-free signal that -post-scan-hook has actually begun —
	// the cross-process equivalent of waiting on a channel.
	//nolint:gosec // G204: binPath and the hook command are entirely test-constructed, not attacker-controlled input
	cmd := exec.CommandContext(ctx, binPath,
		"-post-scan-hook", "echo hook-started && sleep 30",
		"-hook-timeout", "60s",
		url,
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("getting subprocess stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting subprocess: %v", err)
	}

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("subprocess never reached the target")
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("sending first SIGINT: %v", err)
	}

	hookStarted := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if scanner.Text() == "hook-started" {
				close(hookStarted)
				return
			}
		}
	}()
	select {
	case <-hookStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("subprocess's post-scan hook never started")
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("sending second SIGINT: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("subprocess exit error = %v (%T), want *exec.ExitError from a signal kill", err, err)
		}
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() {
			t.Fatalf("subprocess exit state = %v, want terminated by a signal", exitErr.ProcessState)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("subprocess did not exit promptly after the second SIGINT, want it killed immediately instead of waiting out the 30s hook")
	}
}
