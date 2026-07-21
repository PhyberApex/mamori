package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func main() {
	if err := run(os.Args[1:], stdinIfPiped(), os.Stdout); err != nil {
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
	urls, err := scanner.ResolveTargets(args, stdin)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	findings, err := scanner.Scan(context.Background(), client, scanner.DefaultCheckers(), urls)
	if err != nil {
		return err
	}
	return scanner.TerminalReporter{}.Report(findings, out)
}
