package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

func ResolveTargets(args []string, stdin io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	targets := make([]string, 0, len(args))
	add := func(target string) error {
		if err := validateTarget(target); err != nil {
			return err
		}
		if _, ok := seen[target]; ok {
			return nil
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
		return nil
	}

	for _, arg := range args {
		if err := add(arg); err != nil {
			return nil, err
		}
	}
	if stdin != nil {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if err := add(line); err != nil {
				return nil, err
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets: pass URLs as arguments or pipe them via stdin")
	}
	return targets, nil
}

func validateTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", target, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid URL %q: must start with http:// or https:// and include a host", target)
	}
	return nil
}
