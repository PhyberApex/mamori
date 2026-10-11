package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PhyberApex/mamori/internal/config"
	"github.com/PhyberApex/mamori/internal/scanner"
)

// errFailThreshold signals that -fail-on tripped on the scan's own findings,
// not that the scan malfunctioned. main() checks for it specifically so it
// can exit non-zero without the "mamori: ..." line a real failure gets — the
// report already written to out has told the user exactly what's wrong, so
// repeating that as a generic error would just be noise.
var errFailThreshold = errors.New("findings at or above the -fail-on threshold")

// errInterrupted signals that a SIGINT/SIGTERM arrived mid-scan. main()
// checks for it specifically so it can route to its own exit code, taking
// priority over both a Hook failure and -fail-on even when either also
// trips on the same run.
var errInterrupted = errors.New("scan interrupted")

// version reports the build's release version. goreleaser overwrites it via
// -ldflags "-X main.version={{.Version}}"; a plain `go build`/`go run` never
// sets that flag, so it stays at this fallback.
var version = "dev"

func main() {
	err := run(os.Args[1:], stdinIfPiped(), os.Stdout)
	// -h/-help surfaces as flag.ErrHelp after the FlagSet has already
	// printed usage; that is a clean exit, not a failure.
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil && !errors.Is(err, errFailThreshold) {
		fmt.Fprintln(os.Stderr, "mamori:", err)
	}
	os.Exit(exitCode(err))
}

// exitCode maps a run() error to the process exit code a CI caller relies
// on to tell apart why mamori exited non-zero, without parsing stderr: an
// interrupted scan (4) takes priority over a Hook failure (3), which takes
// priority over a tripped -fail-on gate (1), which in turn takes priority
// over any other error (2) — matching the priority run() already gives
// these conditions over each other when choosing which error to return.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errInterrupted):
		return 4
	case errors.Is(err, errHookFailed):
		return 3
	case errors.Is(err, errFailThreshold):
		return 1
	default:
		return 2
	}
}

// stdinIfPiped returns os.Stdin only when data is piped in; when stdin is the
// terminal, reading it would block waiting for the user to type.
func stdinIfPiped() io.Reader {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	return os.Stdin
}

// colorEnabled reports whether TerminalReporter should style its output: only
// when out is an interactive terminal and NO_COLOR is unset.
func colorEnabled(out io.Writer) bool {
	return !noColorSet() && isTerminal(out)
}

// noColorSet reports whether NO_COLOR is present in the environment. Per
// https://no-color.org, presence alone disables color, so this checks
// LookupEnv rather than treating the value as a flag to parse.
func noColorSet() bool {
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}

// isTerminal reports whether w is an interactive terminal (a character
// device), mirroring how stdinIfPiped detects ttyness via Stat() on the
// other side of the pipe.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	cfg, targets, err := config.Resolve(args, os.Getenv)
	if err != nil {
		return err
	}
	if cfg.Version {
		if _, err := fmt.Fprintln(out, version); err != nil {
			return err
		}
		return nil
	}
	urls, err := scanner.ResolveTargets(targets, stdin)
	if err != nil {
		return err
	}

	// Hooks run against a plain, uncancelable context: both must stay bounded
	// only by -hook-timeout, regardless of whether the scan below is
	// interrupted (see scanCtx) — in particular -post-scan-hook still needs
	// its chance to run, e.g. to re-enable a WAF -pre-scan-hook disabled,
	// even when the scan itself didn't finish.
	hookCtx := context.Background()
	if _, err := runHook(hookCtx, cfg.PreScanHook, hookPhasePre, urls, cfg.HookTimeout, os.Stderr); err != nil {
		return err
	}

	// scanCtx is canceled by the first SIGINT/SIGTERM mamori receives, only
	// for the duration of the scan phase. The goroutine below restores
	// default OS signal disposition as soon as that happens (rather than
	// waiting for the scan to actually finish unwinding), so a second signal
	// — most likely to land while -post-scan-hook is running below — kills
	// the process immediately instead of being caught again.
	scanCtx, stopNotify := signal.NotifyContext(hookCtx, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-scanCtx.Done()
		stopNotify()
	}()

	client := &http.Client{Timeout: cfg.Timeout}
	if cfg.Rate > 0 {
		// client.Timeout alone can't be reused here: it starts counting
		// from Do(), before the limiter even runs, so it would wrongly
		// charge queue-wait time against the request's budget. A
		// RateLimitedTransport enforces -timeout itself instead, per
		// individual request, starting only once the limiter releases it —
		// which is deliberately a *different* timeout scope than
		// client.Timeout's whole-redirect-chain one (see README's -rate
		// section), so this can't be collapsed into a single code path
		// that behaves identically whether or not -rate is set.
		client.Timeout = 0
		client.Transport = scanner.NewRateLimitedTransport(nil, cfg.Rate, cfg.Timeout)
	}
	pathCheckers := scanner.PathCheckersFor(cfg.CheckExposedPaths, cfg.ExtraExposedPaths)
	findings := scanner.Scan(scanCtx, client, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), pathCheckers, urls, cfg.Workers, http.Header(cfg.Headers))
	interrupted := scanCtx.Err() != nil
	// Stop watching for signals the instant the scan phase ends, win or
	// lose: the handler above is scoped to "around the scan phase" only, so
	// -post-scan-hook below always runs under default signal disposition,
	// whether or not this particular scan was interrupted.
	stopNotify()
	scanner.ApplySuppressions(findings, cfg.Suppressions, time.Now(), os.Stderr)
	scanner.ApplyBaseline(findings, cfg.Baseline)

	// The post-scan hook's job (e.g. re-enabling a WAF the pre-scan hook
	// disabled) must run whether or not the scan produced findings, so its
	// result is held until after the report is written rather than
	// short-circuiting here.
	_, hookErr := runHook(hookCtx, cfg.PostScanHook, hookPhasePost, urls, cfg.HookTimeout, os.Stderr)

	if err := reporterFor(cfg, out).Report(findings, out); err != nil {
		return err
	}
	// An interrupted scan outranks even a hookErr from the post-scan Hook
	// above: unlike the hookErr-vs-fail-on choice below, which picks the
	// more actionable of two routine conditions, an interrupt means the
	// *caller* cut the run short, which is the more unusual fact here and
	// the one most worth surfacing distinctly, even at the cost of masking
	// a Hook failure's own detail.
	if interrupted {
		return errInterrupted
	}
	// hookErr takes priority over -fail-on when both trip: the report above
	// already surfaced whichever findings crossed the -fail-on threshold, so
	// the exit code is non-zero either way, but the *hook* failing is the
	// more actionable, unusual problem (e.g. a WAF that may still be
	// disabled) and must not be silently swapped for the routine "findings
	// crossed the threshold" case.
	if hookErr != nil {
		return hookErr
	}
	if scanner.AnyFails(findings, cfg.FailOn) {
		return errFailThreshold
	}
	return nil
}

// reporterFor returns the Reporter interface, not a concrete type, so run
// stays indifferent to which implementation it drives — the Go way of
// selecting a strategy is a small interface plus a switch at the edge. It
// takes the whole Config, not just cfg.Output, because SarifReporter also
// needs to know whether a -baseline was supplied (see
// SarifReporter.BaselineSupplied).
func reporterFor(cfg config.Config, out io.Writer) scanner.Reporter {
	switch cfg.Output {
	case config.OutputJSON:
		return scanner.JSONReporter{}
	case config.OutputSarif:
		return scanner.SarifReporter{BaselineSupplied: cfg.BaselinePath != ""}
	default:
		return scanner.TerminalReporter{Color: colorEnabled(out)}
	}
}
