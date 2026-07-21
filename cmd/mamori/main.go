package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mamori:", err)
		os.Exit(1)
	}
}

func run(urls []string, out io.Writer) error {
	if len(urls) == 0 {
		return errors.New("usage: mamori <url> [<url>...]")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	findings, err := scanner.Scan(context.Background(), client, scanner.DefaultCheckers(), urls)
	if err != nil {
		return err
	}
	return scanner.TerminalReporter{}.Report(findings, out)
}
