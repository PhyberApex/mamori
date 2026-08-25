// Package config resolves runtime settings once at startup with the
// precedence: hardcoded default → config file → environment variable → CLI flag.
package config

import (
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
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
	OutputSarif    Output = "sarif"
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
	// Version is set by -v/-version. The caller checks it and short-circuits
	// before resolving targets or scanning, mirroring flag.ErrHelp's -h
	// short-circuit — neither validates the rest of Config first.
	Version bool
	// Headers holds the -H flags, applied to every scan request. The zero
	// value (nil) is already the correct default: no extra headers.
	Headers Headers
}

// Headers is http.Header under the flag package's Value contract: a defined
// type so *Headers can carry String/Set methods, since those can't be added
// to http.Header itself. -H is repeatable, so Set accumulates rather than
// replacing on each call.
type Headers http.Header

// String and Set make *Headers satisfy flag.Value, the same hook Output and
// FailOn use above. String renders back in the same "Key: Value" form Set
// accepts, sorted for determinism, rather than Go's raw map syntax.
func (h *Headers) String() string {
	keys := make([]string, 0, len(*h))
	for k := range *h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + http.Header(*h).Get(k)
	}
	return strings.Join(parts, ", ")
}

// Set parses a single curl-style "Key: Value" header. A key repeated across
// multiple -H flags follows http.Header.Set's last-value-wins rule, matching
// the "apply via req.Header.Set" behaviour the request path uses.
func (h *Headers) Set(v string) error {
	key, value, ok := strings.Cut(v, ":")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return fmt.Errorf("%q is not in \"Key: Value\" form", v)
	}
	if *h == nil {
		*h = Headers{}
	}
	http.Header(*h).Set(key, strings.TrimSpace(value))
	return nil
}

func parseOutput(v string) (Output, error) {
	switch Output(v) {
	case OutputTerminal, OutputJSON, OutputSarif:
		return Output(v), nil
	}
	return "", fmt.Errorf("%q is not a known output format (terminal, json, sarif)", v)
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
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("output: must be a string, not %s", describeYAMLKind(value.Kind))
	}
	if err := o.Set(value.Value); err != nil {
		return fmt.Errorf("output: %w", err)
	}
	return nil
}

// describeYAMLKind names a yaml.Node's Kind for the UnmarshalYAML error
// message above, so a wrong-typed output value (e.g. a list) reports what
// was actually found instead of being mistaken for an empty string.
func describeYAMLKind(kind yaml.Kind) string {
	switch kind {
	case yaml.SequenceNode:
		return "a list"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "that value"
	}
}

// validateWorkers reports whether n satisfies the "positive integer" rule
// the config-file, env, and flag layers all enforce for -workers.
func validateWorkers(n int) error {
	if n < 1 {
		return fmt.Errorf("%d is not a positive integer", n)
	}
	return nil
}

// validateTimeout reports whether d satisfies the "positive duration" rule
// the config-file, env, and flag layers all enforce for -timeout.
func validateTimeout(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("%v is not a positive duration", d)
	}
	return nil
}

// registerFlags builds the FlagSet mamori parses args with, wiring each flag
// straight into cfg. The returned configPath pointer is populated by -config
// but, in the real parse, resolveConfigPath's prescan has already resolved
// and applied the config-file layer before this runs (see loadConfigLayer);
// it is registered here purely so -config is recognized by Parse and
// documented in -h. The prescan reuses this same registration so its parse
// of -config agrees with the real parse on exactly where flag parsing stops
// and on last-flag-wins for a repeated -config, instead of hand-rolling a
// second, divergent parser.
func registerFlags(cfg *Config) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("mamori", flag.ContinueOnError)
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "number of concurrent scan workers")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "HTTP request timeout (e.g. 5s)")
	fs.Var(&cfg.Output, "o", "output format: terminal, json, or sarif")
	fs.Var(&cfg.FailOn, "fail-on", "exit non-zero on findings at or above this severity: low, medium, high, or none")
	fs.BoolVar(&cfg.Version, "v", false, "print version and exit")
	fs.BoolVar(&cfg.Version, "version", false, "print version and exit")
	fs.Var(&cfg.Headers, "H", "custom request header 'Key: Value', e.g. -H 'Authorization: Bearer xyz' (repeatable)")
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to YAML config file (env MAMORI_CONFIG; default: .mamori.yaml in the working directory if present)")
	return fs, &configPath
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
		if err != nil || validateWorkers(n) != nil {
			return Config{}, nil, fmt.Errorf("MAMORI_WORKERS: %q is not a positive integer", v)
		}
		cfg.Workers = n
	}
	if v := getenv("MAMORI_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || validateTimeout(d) != nil {
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

	fs, _ := registerFlags(&cfg)
	if err := fs.Parse(args); err != nil {
		return Config{}, nil, err
	}
	if cfg.Version {
		return cfg, nil, nil
	}
	if err := validateWorkers(cfg.Workers); err != nil {
		return Config{}, nil, fmt.Errorf("-workers: %w", err)
	}
	if err := validateTimeout(cfg.Timeout); err != nil {
		return Config{}, nil, fmt.Errorf("-timeout: %w", err)
	}
	targets := append(append([]string{}, fileTargets...), fs.Args()...)
	return cfg, targets, nil
}
