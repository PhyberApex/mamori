package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// autoDiscoverPath is the config file mamori looks for in the working
// directory when neither -config nor MAMORI_CONFIG names one explicitly.
const autoDiscoverPath = ".mamori.yaml"

// fileConfig mirrors the subset of Config a YAML config file may set. Fields
// are pointers so the loader can tell "absent" apart from "explicitly zero"
// and only override what the file actually sets.
type fileConfig struct {
	Targets []string `yaml:"targets"`
	Workers *int     `yaml:"workers"`
	Timeout *string  `yaml:"timeout"`
	Output  *Output  `yaml:"output"`
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

// prescanConfigFlag looks for -config/--config ahead of the full flag.Parse
// call in Resolve: the config file has to be loaded before it can seed the
// flag defaults that establish the default → config → env → flag precedence.
// A malformed -config usage (e.g. a missing value) is left for flag.Parse to
// reject with its usual error rather than being handled here.
func prescanConfigFlag(args []string) string {
	for i, arg := range args {
		switch {
		case arg == "-config" || arg == "--config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return ""
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
		if *fc.Workers < 1 {
			return fmt.Errorf("%s: workers: %d is not a positive integer", path, *fc.Workers)
		}
		cfg.Workers = *fc.Workers
	}
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("%s: timeout: %q is not a positive duration (e.g. 5s)", path, *fc.Timeout)
		}
		cfg.Timeout = d
	}
	if fc.Output != nil {
		cfg.Output = *fc.Output
	}
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
