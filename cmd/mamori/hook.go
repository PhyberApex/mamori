package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// hookPhase identifies which point in the scan lifecycle a hook is running
// for, surfaced to the hook's subprocess via MAMORI_HOOK_PHASE so one script
// can branch on pre vs. post if it needs to.
type hookPhase string

const (
	hookPhasePre  hookPhase = "pre"
	hookPhasePost hookPhase = "post"
)

// runHook runs command as a shell command once, if command is non-empty. It
// is a no-op (ran=false, err=nil) when command is empty, so callers can tell
// "no hook configured" apart from "hook ran and failed". The subprocess
// receives the resolved target list via MAMORI_HOOK_TARGETS (one target per
// line) and which phase it's running as via MAMORI_HOOK_PHASE; its stdout
// and stderr are both routed to stderr, never to mamori's own stdout, so a
// hook's own output can't corrupt -o json/sarif output.
func runHook(ctx context.Context, command string, phase hookPhase, targets []string, timeout time.Duration, stderr io.Writer) (ran bool, err error) {
	if command == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // G204: command is the user's own -pre-scan-hook/-post-scan-hook config, not attacker-controlled input
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Env = append(cmd.Environ(),
		"MAMORI_HOOK_PHASE="+string(phase),
		"MAMORI_HOOK_TARGETS="+strings.Join(targets, "\n"),
	)
	cmd.Stdout = stderr
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return true, fmt.Errorf("%s-scan hook timed out after %v", phase, timeout)
		}
		return true, fmt.Errorf("%s-scan hook: %w", phase, err)
	}
	return true, nil
}
