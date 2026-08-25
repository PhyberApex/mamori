package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/PhyberApex/mamori/internal/config"
	"github.com/PhyberApex/mamori/internal/scanner"
)

// errFailThreshold signals that -fail-on tripped on the scan's own findings,
// not that the scan malfunctioned. main() checks for it specifically so it
// can exit non-zero without the "mamori: ..." line a real failure gets — the
// report already written to out has told the user exactly what's wrong, so
// repeating that as a generic error would just be noise.
var errFailThreshold = errors.New("findings at or above the -fail-on threshold")

// version reports the build's release version. goreleaser overwrites it via
// -ldflags "-X main.version={{.Version}}"; a plain `go build`/`go run` never
// sets that flag, so it stays at this fallback.
var version = "dev"

func main() {
	if err := run(os.Args[1:], stdinIfPiped(), os.Stdout); err != nil {
		// -h/-help surfaces as flag.ErrHelp after the FlagSet has already
		// printed usage; that is a clean exit, not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if !errors.Is(err, errFailThreshold) {
			fmt.Fprintln(os.Stderr, "mamori:", err)
		}
		os.Exit(1)
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
	client := &http.Client{Timeout: cfg.Timeout}
	findings := scanner.Scan(context.Background(), client, scanner.DefaultCheckers(), scanner.DefaultBodyCheckers(), urls, cfg.Workers, http.Header(cfg.Headers))
	if err := reporterFor(cfg.Output).Report(findings, out); err != nil {
		return err
	}
	if scanner.AnyFails(findings, cfg.FailOn) {
		return errFailThreshold
	}
	return nil
}

// reporterFor returns the Reporter interface, not a concrete type, so run
// stays indifferent to which implementation it drives — the Go way of
// selecting a strategy is a small interface plus a switch at the edge.
func reporterFor(o config.Output) scanner.Reporter {
	switch o {
	case config.OutputJSON:
		return scanner.JSONReporter{}
	case config.OutputSarif:
		return scanner.SarifReporter{}
	default:
		return scanner.TerminalReporter{}
	}
}
