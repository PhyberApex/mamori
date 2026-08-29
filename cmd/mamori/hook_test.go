package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunHookNoCommandIsNoop(t *testing.T) {
	var stderr bytes.Buffer
	ran, err := runHook(context.Background(), "", hookPhasePre, nil, time.Second, &stderr)
	if ran {
		t.Error("runHook() with an empty command ran = true, want false")
	}
	if err != nil {
		t.Errorf("runHook() with an empty command returned %v, want nil", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("runHook() with an empty command wrote %q to stderr, want nothing", stderr.String())
	}
}

func TestRunHookRunsCommandAndReportsSuccess(t *testing.T) {
	var stderr bytes.Buffer
	ran, err := runHook(context.Background(), "exit 0", hookPhasePre, nil, time.Second, &stderr)
	if !ran {
		t.Error("runHook() with a command ran = false, want true")
	}
	if err != nil {
		t.Errorf("runHook() with a succeeding command returned %v, want nil", err)
	}
}

func TestRunHookReportsNonZeroExit(t *testing.T) {
	var stderr bytes.Buffer
	ran, err := runHook(context.Background(), "exit 3", hookPhasePost, nil, time.Second, &stderr)
	if !ran {
		t.Error("runHook() with a failing command ran = false, want true")
	}
	if err == nil {
		t.Fatal("runHook() with a failing command returned nil error, want error")
	}
	if !strings.Contains(err.Error(), "post-scan hook") {
		t.Errorf("runHook() error = %q, want it to name the post-scan hook", err.Error())
	}
}

func TestRunHookReportsTimeout(t *testing.T) {
	var stderr bytes.Buffer
	ran, err := runHook(context.Background(), "sleep 5", hookPhasePre, nil, 20*time.Millisecond, &stderr)
	if !ran {
		t.Error("runHook() with a command that times out ran = false, want true")
	}
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("runHook() error = %v, want a timeout error", err)
	}
}

func TestRunHookPassesPhaseAndTargetsAsEnvVars(t *testing.T) {
	var stderr bytes.Buffer
	_, err := runHook(
		context.Background(),
		`test "$MAMORI_HOOK_PHASE" = "pre" && test "$MAMORI_HOOK_TARGETS" = "$(printf 'https://a.example\nhttps://b.example')"`,
		hookPhasePre,
		[]string{"https://a.example", "https://b.example"},
		time.Second,
		&stderr,
	)
	if err != nil {
		t.Errorf("runHook() did not see expected env vars: %v\nstderr:\n%s", err, stderr.String())
	}
}

func TestRunHookRoutesOutputToStderrNotStdout(t *testing.T) {
	var stderr bytes.Buffer
	ran, err := runHook(context.Background(), "echo hello-from-hook", hookPhasePre, nil, time.Second, &stderr)
	if !ran || err != nil {
		t.Fatalf("runHook() = (%v, %v), want (true, nil)", ran, err)
	}
	if !strings.Contains(stderr.String(), "hello-from-hook") {
		t.Errorf("runHook() stderr = %q, want it to contain the hook's output", stderr.String())
	}
}
