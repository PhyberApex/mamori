// Package config resolves runtime settings once at startup with the
// precedence: hardcoded default → environment variable → CLI flag.
package config

import (
	"flag"
	"fmt"
	"strconv"
	"time"
)

const (
	defaultWorkers = 10
	defaultTimeout = 10 * time.Second
)

type Config struct {
	Workers int
	Timeout time.Duration
}

// Resolve takes getenv as a function value instead of calling os.Getenv
// directly, so tests can inject environment values without mutating real
// process state. The env-resolved values are used as the flag defaults,
// which encodes the precedence chain and makes -h show effective defaults.
func Resolve(args []string, getenv func(string) string) (Config, []string, error) {
	cfg := Config{Workers: defaultWorkers, Timeout: defaultTimeout}

	if v := getenv("MAMORI_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, nil, fmt.Errorf("MAMORI_WORKERS: %q is not a positive integer", v)
		}
		cfg.Workers = n
	}
	if v := getenv("MAMORI_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, nil, fmt.Errorf("MAMORI_TIMEOUT: %q is not a positive duration (e.g. 5s)", v)
		}
		cfg.Timeout = d
	}

	fs := flag.NewFlagSet("mamori", flag.ContinueOnError)
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "number of concurrent scan workers")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "HTTP request timeout (e.g. 5s)")
	if err := fs.Parse(args); err != nil {
		return Config{}, nil, err
	}
	if cfg.Workers < 1 {
		return Config{}, nil, fmt.Errorf("-workers: %d is not a positive integer", cfg.Workers)
	}
	if cfg.Timeout <= 0 {
		return Config{}, nil, fmt.Errorf("-timeout: %v is not a positive duration", cfg.Timeout)
	}
	return cfg, fs.Args(), nil
}
