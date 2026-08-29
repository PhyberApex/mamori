package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PhyberApex/mamori/internal/scanner"
	"gopkg.in/yaml.v3"
)

// autoDiscoverPath is the config file mamori looks for in the working
// directory when neither -config nor MAMORI_CONFIG names one explicitly.
const autoDiscoverPath = ".mamori.yaml"

// fileConfig mirrors the subset of Config a YAML config file may set. Fields
// are pointers so the loader can tell "absent" apart from "explicitly zero"
// and only override what the file actually sets.
type fileConfig struct {
	Targets      []string              `yaml:"targets"`
	Workers      *int                  `yaml:"workers"`
	Timeout      *string               `yaml:"timeout"`
	Output       *Output               `yaml:"output"`
	Suppressions []scanner.Suppression `yaml:"suppressions"`
	// CheckExposedPaths and ExposedPaths mirror the -check-exposed-paths and
	// -exposed-path flags. ExposedPaths has no env var, following the -H
	// flag's precedent for a repeatable list-shaped setting.
	CheckExposedPaths *bool    `yaml:"checkExposedPaths"`
	ExposedPaths      []string `yaml:"exposedPaths"`
	PreScanHook       *string  `yaml:"pre_scan_hook"`
	PostScanHook      *string  `yaml:"post_scan_hook"`
	HookTimeout       *string  `yaml:"hook_timeout"`
}

// resolveConfigPath decides which config file, if any, supplies the config
// layer. An explicit -config flag or MAMORI_CONFIG env var must name a file
// that exists — checked by the caller when it loads the file — while the
// .mamori.yaml auto-discovery path is allowed to not exist, since absence
// there just means "no config file" rather than a misconfiguration.
func resolveConfigPath(args []string, getenv func(string) string) (path string, explicit bool) {
	if v := prescanConfigFlag(args); v != "" {
		return v, true
	}
	if v := getenv("MAMORI_CONFIG"); v != "" {
		return v, true
	}
	return autoDiscoverPath, false
}

// prescanConfigFlag looks for -config ahead of the full flag.Parse call in
// Resolve: the config file has to be loaded before it can seed the flag
// defaults that establish the default → config → env → flag precedence. It
// parses with the same registerFlags definitions the real parse uses, so
// this prescan agrees with flag.Parse on exactly where flag parsing stops
// (e.g. at the first positional target argument) and on last-flag-wins for
// a repeated -config, rather than a hand-rolled scan that could disagree
// with flag.Parse about which -config occurrence, if any, applies. A
// malformed usage is left for the real Parse call to reject with its usual
// error rather than being handled here.
func prescanConfigFlag(args []string) string {
	var cfg Config
	fs, configPath := registerFlags(&cfg)
	fs.SetOutput(io.Discard)
	_ = fs.Parse(args)
	return *configPath
}

func loadConfigFile(path string) (fileConfig, error) {
	//nolint:gosec // G304 false positive: path is the user's own -config/MAMORI_CONFIG/.mamori.yaml selection, not attacker-controlled input
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fileConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return fc, nil
}

// applyFileConfig overrides cfg with any fields fc sets, validating with the
// same rules the env and flag stages already enforce so a bad config file
// fails the same way a bad env var or flag would.
func applyFileConfig(cfg *Config, fc fileConfig, path string) error {
	if fc.Workers != nil {
		if err := validateWorkers(*fc.Workers); err != nil {
			return fmt.Errorf("%s: workers: %w", path, err)
		}
		cfg.Workers = *fc.Workers
	}
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err != nil || validateTimeout(d) != nil {
			return fmt.Errorf("%s: timeout: %q is not a positive duration (e.g. 5s)", path, *fc.Timeout)
		}
		cfg.Timeout = d
	}
	if fc.Output != nil {
		cfg.Output = *fc.Output
	}
	if fc.PreScanHook != nil {
		cfg.PreScanHook = *fc.PreScanHook
	}
	if fc.PostScanHook != nil {
		cfg.PostScanHook = *fc.PostScanHook
	}
	if fc.HookTimeout != nil {
		d, err := time.ParseDuration(*fc.HookTimeout)
		if err != nil || validateHookTimeout(d) != nil {
			return fmt.Errorf("%s: hook_timeout: %q is not a positive duration (e.g. 30s)", path, *fc.HookTimeout)
		}
		cfg.HookTimeout = d
	}
	if err := validateSuppressions(fc.Suppressions); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cfg.Suppressions = fc.Suppressions
	if fc.CheckExposedPaths != nil {
		cfg.CheckExposedPaths = *fc.CheckExposedPaths
	}
	// Additive, not a replace: applyFileConfig runs before the -exposed-path
	// flag is parsed, so appending here lets a repeated -exposed-path flag
	// extend what the config file already set rather than clobbering it.
	cfg.ExtraExposedPaths = append(cfg.ExtraExposedPaths, fc.ExposedPaths...)
	return nil
}

// loadConfigLayer resolves and applies the config-file layer onto cfg,
// returning any targets the file declares. It is a no-op, without error,
// when auto-discovery finds nothing — explicit selection via -config or
// MAMORI_CONFIG must resolve to a real, valid file.
func loadConfigLayer(cfg *Config, args []string, getenv func(string) string) ([]string, error) {
	path, explicit := resolveConfigPath(args, getenv)
	fc, err := loadConfigFile(path)
	switch {
	case err == nil:
		if err := applyFileConfig(cfg, fc, path); err != nil {
			return nil, err
		}
		return fc.Targets, nil
	case explicit:
		return nil, fmt.Errorf("config: %w", err)
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("config: %w", err)
	}
}
