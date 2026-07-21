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

func main() {
	if err := run(os.Args[1:], stdinIfPiped(), os.Stdout); err != nil {
		// -h/-help surfaces as flag.ErrHelp after the FlagSet has already
		// printed usage; that is a clean exit, not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "mamori:", err)
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
	urls, err := scanner.ResolveTargets(targets, stdin)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: cfg.Timeout}
	findings := scanner.Scan(context.Background(), client, scanner.DefaultCheckers(), urls, cfg.Workers)
	return scanner.TerminalReporter{}.Report(findings, out)
}
