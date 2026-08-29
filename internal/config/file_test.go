package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/config"
)

func writeConfigFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	return path
}

func TestResolveConfigFlagLoadsWorkersTimeoutOutputAndTargets(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
workers: 4
timeout: 3s
output: json
targets:
  - https://from-config.example
`)

	cfg, targets, err := config.Resolve([]string{"-config", path}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 4 {
		t.Errorf("Workers = %d, want 4 from config file", cfg.Workers)
	}
	if cfg.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s from config file", cfg.Timeout)
	}
	if cfg.Output != config.OutputJSON {
		t.Errorf("Output = %q, want %q from config file", cfg.Output, config.OutputJSON)
	}
	if len(targets) != 1 || targets[0] != "https://from-config.example" {
		t.Errorf("targets = %v, want [https://from-config.example]", targets)
	}
}

func TestResolveConfigEnvVarSelectsFile(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `workers: 7`)

	cfg, _, err := config.Resolve(nil, envWith(map[string]string{"MAMORI_CONFIG": path}))
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 7 {
		t.Errorf("Workers = %d, want 7 from MAMORI_CONFIG file", cfg.Workers)
	}
}

func TestResolveConfigFlagOverridesConfigEnvVar(t *testing.T) {
	flagPath := writeConfigFile(t, t.TempDir(), "flag.yaml", `workers: 5`)
	envPath := writeConfigFile(t, t.TempDir(), "env.yaml", `workers: 9`)

	cfg, _, err := config.Resolve(
		[]string{"-config", flagPath},
		envWith(map[string]string{"MAMORI_CONFIG": envPath}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers = %d, want 5 from -config flag overriding MAMORI_CONFIG", cfg.Workers)
	}
}

func TestResolveEnvVarOverridesConfigFile(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `workers: 3`)

	cfg, _, err := config.Resolve(
		[]string{"-config", path},
		envWith(map[string]string{"MAMORI_WORKERS": "8"}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers = %d, want 8 from MAMORI_WORKERS overriding config file", cfg.Workers)
	}
}

func TestResolveFlagOverridesConfigFile(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `workers: 3`)

	cfg, _, err := config.Resolve([]string{"-config", path, "-workers", "6"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 6 {
		t.Errorf("Workers = %d, want 6 from -workers flag overriding config file", cfg.Workers)
	}
}

func TestResolveConfigFileTargetsMergeAdditivelyWithArgs(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
targets:
  - https://from-config.example
`)

	_, targets, err := config.Resolve([]string{"-config", path, "https://from-args.example"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	want := map[string]bool{"https://from-config.example": true, "https://from-args.example": true}
	if len(targets) != len(want) {
		t.Fatalf("targets = %v, want two entries", targets)
	}
	for _, target := range targets {
		if !want[target] {
			t.Errorf("unexpected target %q", target)
		}
	}
}

func TestResolveConfigFlagLastOccurrenceWins(t *testing.T) {
	first := writeConfigFile(t, t.TempDir(), "first.yaml", `workers: 3`)
	second := writeConfigFile(t, t.TempDir(), "second.yaml", `workers: 9`)

	cfg, _, err := config.Resolve([]string{"-config", first, "-config", second}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 9 {
		t.Errorf("Workers = %d, want 9 from the second -config (last occurrence wins, matching flag.Parse's normal repeated-flag semantics)", cfg.Workers)
	}
}

func TestResolveConfigFlagAfterPositionalArgIsNotRecognized(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := writeConfigFile(t, dir, "should-not-load.yaml", `workers: 99`)

	cfg, targets, err := config.Resolve([]string{"https://example.com", "-config", path}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers = %d, want default 10: flag.Parse stops at the first positional argument, so -config after https://example.com is never reached and must not be treated as an explicit -config selection", cfg.Workers)
	}
	found := false
	for _, target := range targets {
		if target == "https://example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("targets = %v, want https://example.com among them", targets)
	}
}

func TestResolveMissingExplicitConfigFlagErrors(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, noEnv); err == nil {
		t.Error("Resolve() with a missing -config path returned nil error, want error")
	}
}

func TestResolveMissingExplicitConfigEnvVarErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if _, _, err := config.Resolve(nil, envWith(map[string]string{"MAMORI_CONFIG": path})); err == nil {
		t.Error("Resolve() with a missing MAMORI_CONFIG path returned nil error, want error")
	}
}

func TestResolveConfigFileRejectsNonPositiveWorkers(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `workers: 0`)
	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with workers: 0 in config file returned nil error, want error")
	}
}

func TestResolveConfigFileRejectsNonPositiveTimeout(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `timeout: -1s`)
	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with a negative timeout in config file returned nil error, want error")
	}
}

func TestResolveConfigFileRejectsUnknownOutput(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `output: xml`)
	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with an unknown output format in config file returned nil error, want error")
	}
}

func TestResolveConfigFileRejectsNonScalarOutput(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", "output: [terminal, json]\n")
	_, _, err := config.Resolve([]string{"-config", path}, noEnv)
	if err == nil {
		t.Fatal("Resolve() with a non-scalar output in config file returned nil error, want error")
	}
	if strings.Contains(err.Error(), `""`) {
		t.Errorf("Resolve() error = %q, want it to describe the list rather than an empty string", err.Error())
	}
}

func TestResolveConfigFileRejectsInvalidYAML(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", "workers: [this is not an int\n")
	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with malformed YAML in config file returned nil error, want error")
	}
}

func TestResolveAutoDiscoversDotMamoriYAMLInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, ".mamori.yaml", `
workers: 2
targets:
  - https://auto.example
`)
	t.Chdir(dir)

	cfg, targets, err := config.Resolve(nil, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 2 {
		t.Errorf("Workers = %d, want 2 from auto-discovered .mamori.yaml", cfg.Workers)
	}
	if len(targets) != 1 || targets[0] != "https://auto.example" {
		t.Errorf("targets = %v, want [https://auto.example]", targets)
	}
}

func TestResolveConfigFileLoadsSuppressions(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
suppressions:
  - header: Content-Security-Policy
    host: https://cdn.example.com
  - host: https://legacy.example.com
`)

	cfg, _, err := config.Resolve([]string{"-config", path}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if len(cfg.Suppressions) != 2 {
		t.Fatalf("Suppressions = %+v, want 2 entries", cfg.Suppressions)
	}
	if cfg.Suppressions[0].Header != "Content-Security-Policy" || cfg.Suppressions[0].Host != "https://cdn.example.com" {
		t.Errorf("Suppressions[0] = %+v, want header+host pair", cfg.Suppressions[0])
	}
	if cfg.Suppressions[1].Header != "" || cfg.Suppressions[1].Host != "https://legacy.example.com" {
		t.Errorf("Suppressions[1] = %+v, want host-only entry", cfg.Suppressions[1])
	}
}

func TestResolveConfigFileRejectsSuppressionWithNeitherHeaderNorHost(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
suppressions:
  - {}
`)

	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with a suppression entry setting neither header nor host returned nil error, want error")
	}
}

func TestResolveConfigFileLoadsCheckExposedPathsAndExposedPaths(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
checkExposedPaths: true
exposedPaths:
  - debug.log
  - old-backup.sql
`)

	cfg, _, err := config.Resolve([]string{"-config", path}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if !cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = false, want true from config file")
	}
	want := []string{"debug.log", "old-backup.sql"}
	if len(cfg.ExtraExposedPaths) != len(want) {
		t.Fatalf("ExtraExposedPaths = %v, want %v", cfg.ExtraExposedPaths, want)
	}
	for i, p := range want {
		if cfg.ExtraExposedPaths[i] != p {
			t.Errorf("ExtraExposedPaths[%d] = %q, want %q", i, cfg.ExtraExposedPaths[i], p)
		}
	}
}

func TestResolveExposedPathFlagExtendsConfigFileList(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
exposedPaths:
  - debug.log
`)

	cfg, _, err := config.Resolve([]string{"-config", path, "-exposed-path", "old-backup.sql"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	want := map[string]bool{"debug.log": true, "old-backup.sql": true}
	if len(cfg.ExtraExposedPaths) != len(want) {
		t.Fatalf("ExtraExposedPaths = %v, want both the config-file and flag entries", cfg.ExtraExposedPaths)
	}
	for _, p := range cfg.ExtraExposedPaths {
		if !want[p] {
			t.Errorf("unexpected ExtraExposedPaths entry %q", p)
		}
	}
}

func TestResolveConfigFileLoadsHooks(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `
preScanHook: ./disable-waf.sh
postScanHook: ./enable-waf.sh
hookTimeout: 45s
`)

	cfg, _, err := config.Resolve([]string{"-config", path}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.PreScanHook != "./disable-waf.sh" {
		t.Errorf("PreScanHook = %q, want %q from config file", cfg.PreScanHook, "./disable-waf.sh")
	}
	if cfg.PostScanHook != "./enable-waf.sh" {
		t.Errorf("PostScanHook = %q, want %q from config file", cfg.PostScanHook, "./enable-waf.sh")
	}
	if cfg.HookTimeout != 45*time.Second {
		t.Errorf("HookTimeout = %v, want 45s from config file", cfg.HookTimeout)
	}
}

func TestResolveConfigFileRejectsNonPositiveHookTimeout(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `hookTimeout: -1s`)
	if _, _, err := config.Resolve([]string{"-config", path}, noEnv); err == nil {
		t.Error("Resolve() with a negative hookTimeout in config file returned nil error, want error")
	}
}

func TestResolveEnvVarOverridesConfigFileHook(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "mamori.yaml", `preScanHook: ./file-pre.sh`)

	cfg, _, err := config.Resolve(
		[]string{"-config", path},
		envWith(map[string]string{"MAMORI_PRE_SCAN_HOOK": "./env-pre.sh"}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.PreScanHook != "./env-pre.sh" {
		t.Errorf("PreScanHook = %q, want %q from MAMORI_PRE_SCAN_HOOK overriding config file", cfg.PreScanHook, "./env-pre.sh")
	}
}

func TestResolveWithNoConfigFilePresentIsUnchanged(t *testing.T) {
	t.Chdir(t.TempDir())

	cfg, rest, err := config.Resolve([]string{"https://a.example"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers = %d, want default 10 with no config file present", cfg.Workers)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want default 10s with no config file present", cfg.Timeout)
	}
	if cfg.Output != config.OutputTerminal {
		t.Errorf("Output = %q, want default %q with no config file present", cfg.Output, config.OutputTerminal)
	}
	if len(rest) != 1 || rest[0] != "https://a.example" {
		t.Errorf("targets = %v, want [https://a.example]", rest)
	}
}
