// Package config resolves runtime settings once at startup with the
// precedence: hardcoded default → config file → environment variable → CLI flag.
package config

import (
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
	"gopkg.in/yaml.v3"
)

// Output is a named string type so the valid formats live next to the type
// instead of as loose string comparisons scattered through the code. Go has
// no enums; a defined string type plus typed constants is the idiomatic
// stand-in, and it keeps the raw value printable in errors and -h output.
type Output string

const (
	OutputTerminal Output = "terminal"
	OutputJSON     Output = "json"
)

const (
	defaultWorkers = 10
	defaultTimeout = 10 * time.Second
	defaultOutput  = OutputTerminal
)

type Config struct {
	Workers int
	Timeout time.Duration
	Output  Output
	// FailOn is the -fail-on threshold. The zero value ("") is scanner.Severity's
	// own stand-in for "none" — never fail — so Config's zero value is already
	// the correct default without a separate sentinel constant.
	FailOn scanner.Severity
}

func parseOutput(v string) (Output, error) {
	switch Output(v) {
	case OutputTerminal, OutputJSON:
		return Output(v), nil
	}
	return "", fmt.Errorf("%q is not a known output format (terminal, json)", v)
}

// String and Set make *Output satisfy flag.Value, the stdlib's hook for
// custom flag types: the flag package calls Set with the raw argument, so
// validation happens during Parse and bad values fail with a proper flag
// error instead of needing a post-Parse check like the int/duration flags.
func (o *Output) String() string { return string(*o) }

func (o *Output) Set(v string) error {
	parsed, err := parseOutput(v)
	if err != nil {
		return err
	}
	*o = parsed
	return nil
}

// UnmarshalYAML lets the config-file loader decode straight into an Output
// via the same Set used by the flag package, so a config file's output value
// is validated by the one place that already knows what "known format"
// means instead of a second string comparison growing elsewhere.
func (o *Output) UnmarshalYAML(value *yaml.Node) error {
	return o.Set(value.Value)
}

// Resolve takes getenv as a function value instead of calling os.Getenv
// directly, so tests can inject environment values without mutating real
// process state. The env-resolved values are used as the flag defaults,
// which encodes the precedence chain and makes -h show effective defaults.
func Resolve(args []string, getenv func(string) string) (Config, []string, error) {
	cfg := Config{Workers: defaultWorkers, Timeout: defaultTimeout, Output: defaultOutput}

	fileTargets, err := loadConfigLayer(&cfg, args, getenv)
	if err != nil {
		return Config{}, nil, err
	}

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
	if v := getenv("MAMORI_OUTPUT"); v != "" {
		o, err := parseOutput(v)
		if err != nil {
			return Config{}, nil, fmt.Errorf("MAMORI_OUTPUT: %w", err)
		}
		cfg.Output = o
	}
	if v := getenv("MAMORI_FAIL_ON"); v != "" {
		if err := cfg.FailOn.Set(v); err != nil {
			return Config{}, nil, fmt.Errorf("MAMORI_FAIL_ON: %w", err)
		}
	}

	fs := flag.NewFlagSet("mamori", flag.ContinueOnError)
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "number of concurrent scan workers")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "HTTP request timeout (e.g. 5s)")
	fs.Var(&cfg.Output, "o", "output format: terminal or json")
	fs.Var(&cfg.FailOn, "fail-on", "exit non-zero on findings at or above this severity: low, medium, high, or none")
	// configPath is resolved and applied above, before the flag defaults are
	// established; it is registered here purely so -config is recognized by
	// Parse and documented in -h, not read back after Parse.
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to YAML config file (env MAMORI_CONFIG; default: .mamori.yaml in the working directory if present)")
	if err := fs.Parse(args); err != nil {
		return Config{}, nil, err
	}
	if cfg.Workers < 1 {
		return Config{}, nil, fmt.Errorf("-workers: %d is not a positive integer", cfg.Workers)
	}
	if cfg.Timeout <= 0 {
		return Config{}, nil, fmt.Errorf("-timeout: %v is not a positive duration", cfg.Timeout)
	}
	targets := append(append([]string{}, fileTargets...), fs.Args()...)
	return cfg, targets, nil
}
