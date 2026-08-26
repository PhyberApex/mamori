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
	// Suppressions holds the config-file "suppressions" list, marking
	// Findings as an accepted risk or known false positive. There is no
	// flag/env equivalent — the config file is the only place these are
	// set — so the zero value (nil) is already the correct default: no
	// suppressions.
	Suppressions []scanner.Suppression
	// CheckExposedPaths turns on the sensitive-path exposure checker
	// category, probing every target's origin for the built-in default path
	// list. Off by default: unlike every other check, it issues requests to
	// paths the user never named as a target — flag + env + config-file,
	// following the pattern workers/timeout/output/fail-on already use.
	CheckExposedPaths bool
	// ExtraExposedPaths adds paths to the default list CheckExposedPaths
	// probes, on top of it rather than instead of it. Supplying at least one
	// entry here enables the category on its own, even when
	// CheckExposedPaths is false — adding a path can't be a silent no-op.
	// The zero value (nil) is already the correct default: no extra paths.
	// Flag + config-file only, no env var, the same pattern -H follows.
	ExtraExposedPaths ExposedPaths
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

// ExposedPaths is a []string under the flag package's Value contract, the
// same wrapper pattern Headers uses above: a defined type so *ExposedPaths
// can carry String/Set methods a plain []string can't. -exposed-path is
// repeatable, so Set appends rather than replacing on each call.
type ExposedPaths []string

func (p *ExposedPaths) String() string { return strings.Join(*p, ", ") }

func (p *ExposedPaths) Set(v string) error {
	*p = append(*p, v)
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

// validateSuppressions reports whether every entry in suppressions sets at
// least one of Header or Host — an entry setting neither is a config error,
// not a silent no-op, since suppressions has no flag/env layer to fall back
// on for this check.
func validateSuppressions(suppressions []scanner.Suppression) error {
	for i, s := range suppressions {
		if s.Header == "" && s.Host == "" {
			return fmt.Errorf("suppressions[%d]: must set at least one of header or host", i)
		}
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
	fs.BoolVar(&cfg.CheckExposedPaths, "check-exposed-paths", cfg.CheckExposedPaths, "probe each target's origin for well-known sensitive paths (.git, .env, backups, ...); off by default since it requests paths beyond the scanned URL itself")
	fs.Var(&cfg.ExtraExposedPaths, "exposed-path", "extra path to probe in addition to the default list, e.g. -exposed-path 'debug.log' (repeatable; also enables -check-exposed-paths)")
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
	if v := getenv("MAMORI_CHECK_EXPOSED_PATHS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, nil, fmt.Errorf("MAMORI_CHECK_EXPOSED_PATHS: %q is not a valid boolean (true/false)", v)
		}
		cfg.CheckExposedPaths = b
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
