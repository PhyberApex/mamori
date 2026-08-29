package config_test

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/config"
	"github.com/PhyberApex/mamori/internal/scanner"
)

func noEnv(string) string { return "" }

func envWith(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestResolveDefaults(t *testing.T) {
	cfg, rest, err := config.Resolve([]string{"https://a.example"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers = %d, want default 10", cfg.Workers)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want default 10s", cfg.Timeout)
	}
	if len(rest) != 1 || rest[0] != "https://a.example" {
		t.Errorf("remaining args = %v, want [https://a.example]", rest)
	}
	if cfg.Output != config.OutputTerminal {
		t.Errorf("Output = %q, want default %q", cfg.Output, config.OutputTerminal)
	}
	if cfg.FailOn != "" {
		t.Errorf("FailOn = %q, want zero value (\"none\")", cfg.FailOn)
	}
	if cfg.PreScanHook != "" {
		t.Errorf("PreScanHook = %q, want empty default", cfg.PreScanHook)
	}
	if cfg.PostScanHook != "" {
		t.Errorf("PostScanHook = %q, want empty default", cfg.PostScanHook)
	}
	if cfg.HookTimeout != 30*time.Second {
		t.Errorf("HookTimeout = %v, want default 30s", cfg.HookTimeout)
	}
}

func TestResolveEnvOverridesDefaults(t *testing.T) {
	cfg, _, err := config.Resolve(nil, envWith(map[string]string{
		"MAMORI_WORKERS": "3",
		"MAMORI_TIMEOUT": "2s",
		"MAMORI_OUTPUT":  "json",
		"MAMORI_FAIL_ON": "medium",
	}))
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 3 {
		t.Errorf("Workers = %d, want 3 from MAMORI_WORKERS", cfg.Workers)
	}
	if cfg.Timeout != 2*time.Second {
		t.Errorf("Timeout = %v, want 2s from MAMORI_TIMEOUT", cfg.Timeout)
	}
	if cfg.Output != config.OutputJSON {
		t.Errorf("Output = %q, want %q from MAMORI_OUTPUT", cfg.Output, config.OutputJSON)
	}
	if cfg.FailOn != scanner.SeverityMedium {
		t.Errorf("FailOn = %q, want %q from MAMORI_FAIL_ON", cfg.FailOn, scanner.SeverityMedium)
	}
}

func TestResolveFlagsOverrideEnv(t *testing.T) {
	cfg, rest, err := config.Resolve(
		[]string{"-workers", "5", "-timeout", "1s", "-o", "terminal", "-fail-on", "high", "https://a.example"},
		envWith(map[string]string{
			"MAMORI_WORKERS": "3",
			"MAMORI_TIMEOUT": "2s",
			"MAMORI_OUTPUT":  "json",
			"MAMORI_FAIL_ON": "low",
		}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers = %d, want 5 from -workers flag", cfg.Workers)
	}
	if cfg.Timeout != 1*time.Second {
		t.Errorf("Timeout = %v, want 1s from -timeout flag", cfg.Timeout)
	}
	if cfg.Output != config.OutputTerminal {
		t.Errorf("Output = %q, want %q from -o flag", cfg.Output, config.OutputTerminal)
	}
	if cfg.FailOn != scanner.SeverityHigh {
		t.Errorf("FailOn = %q, want %q from -fail-on flag", cfg.FailOn, scanner.SeverityHigh)
	}
	if len(rest) != 1 || rest[0] != "https://a.example" {
		t.Errorf("remaining args = %v, want [https://a.example]", rest)
	}
}

func TestResolveEnvSetsHooks(t *testing.T) {
	cfg, _, err := config.Resolve(nil, envWith(map[string]string{
		"MAMORI_PRE_SCAN_HOOK":  "./disable-waf.sh",
		"MAMORI_POST_SCAN_HOOK": "./enable-waf.sh",
		"MAMORI_HOOK_TIMEOUT":   "5s",
	}))
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.PreScanHook != "./disable-waf.sh" {
		t.Errorf("PreScanHook = %q, want %q from MAMORI_PRE_SCAN_HOOK", cfg.PreScanHook, "./disable-waf.sh")
	}
	if cfg.PostScanHook != "./enable-waf.sh" {
		t.Errorf("PostScanHook = %q, want %q from MAMORI_POST_SCAN_HOOK", cfg.PostScanHook, "./enable-waf.sh")
	}
	if cfg.HookTimeout != 5*time.Second {
		t.Errorf("HookTimeout = %v, want 5s from MAMORI_HOOK_TIMEOUT", cfg.HookTimeout)
	}
}

func TestResolveFlagsOverrideHookEnv(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-pre-scan-hook", "./flag-pre.sh", "-post-scan-hook", "./flag-post.sh", "-hook-timeout", "9s"},
		envWith(map[string]string{
			"MAMORI_PRE_SCAN_HOOK":  "./env-pre.sh",
			"MAMORI_POST_SCAN_HOOK": "./env-post.sh",
			"MAMORI_HOOK_TIMEOUT":   "5s",
		}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.PreScanHook != "./flag-pre.sh" {
		t.Errorf("PreScanHook = %q, want %q from -pre-scan-hook flag", cfg.PreScanHook, "./flag-pre.sh")
	}
	if cfg.PostScanHook != "./flag-post.sh" {
		t.Errorf("PostScanHook = %q, want %q from -post-scan-hook flag", cfg.PostScanHook, "./flag-post.sh")
	}
	if cfg.HookTimeout != 9*time.Second {
		t.Errorf("HookTimeout = %v, want 9s from -hook-timeout flag", cfg.HookTimeout)
	}
}

func TestResolveRejectsInvalidHookTimeoutEnv(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
	}{
		{"unparseable hook timeout", map[string]string{"MAMORI_HOOK_TIMEOUT": "fast"}},
		{"negative hook timeout", map[string]string{"MAMORI_HOOK_TIMEOUT": "-1s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := config.Resolve(nil, envWith(tt.vars)); err == nil {
				t.Errorf("Resolve() with %v returned nil error, want error", tt.vars)
			}
		})
	}
}

func TestResolveRejectsNonPositiveHookTimeoutFlag(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-hook-timeout", "0"}, noEnv); err == nil {
		t.Error("Resolve() with -hook-timeout 0 returned nil error, want error")
	}
}

func TestResolveRejectsInvalidEnvValues(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
	}{
		{"non-numeric workers", map[string]string{"MAMORI_WORKERS": "many"}},
		{"zero workers", map[string]string{"MAMORI_WORKERS": "0"}},
		{"negative workers", map[string]string{"MAMORI_WORKERS": "-2"}},
		{"unparseable timeout", map[string]string{"MAMORI_TIMEOUT": "fast"}},
		{"negative timeout", map[string]string{"MAMORI_TIMEOUT": "-1s"}},
		{"unknown output format", map[string]string{"MAMORI_OUTPUT": "xml"}},
		{"unknown fail-on level", map[string]string{"MAMORI_FAIL_ON": "critical"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := config.Resolve(nil, envWith(tt.vars)); err == nil {
				t.Errorf("Resolve() with %v returned nil error, want error", tt.vars)
			}
		})
	}
}

func TestResolveRejectsNonPositiveWorkersFlag(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-workers", "0"}, noEnv); err == nil {
		t.Error("Resolve() with -workers 0 returned nil error, want error")
	}
}

func TestResolveAcceptsSarifOutputFlag(t *testing.T) {
	cfg, _, err := config.Resolve([]string{"-o", "sarif"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.Output != config.OutputSarif {
		t.Errorf("Output = %q, want %q from -o flag", cfg.Output, config.OutputSarif)
	}
}

func TestResolveRejectsUnknownOutputFlag(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-o", "xml"}, noEnv); err == nil {
		t.Error("Resolve() with -o xml returned nil error, want error")
	}
}

func TestResolveRejectsUnknownFailOnFlag(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-fail-on", "critical"}, noEnv); err == nil {
		t.Error("Resolve() with -fail-on critical returned nil error, want error")
	}
}

func TestResolveParsesRepeatableHeaderFlag(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-H", "Authorization: Bearer xyz", "-H", "Cookie: session=abc", "https://a.example"},
		noEnv,
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	want := http.Header{
		"Authorization": {"Bearer xyz"},
		"Cookie":        {"session=abc"},
	}
	if got := http.Header(cfg.Headers); !reflect.DeepEqual(got, want) {
		t.Errorf("Headers = %v, want %v", got, want)
	}
}

func TestResolveHeaderFlagLastValueWinsForRepeatedKey(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-H", "Authorization: first", "-H", "Authorization: second"},
		noEnv,
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if got := http.Header(cfg.Headers).Get("Authorization"); got != "second" {
		t.Errorf("Authorization = %q, want %q (last -H wins)", got, "second")
	}
}

func TestResolveRejectsMalformedHeaderFlag(t *testing.T) {
	if _, _, err := config.Resolve([]string{"-H", "not-a-header"}, noEnv); err == nil {
		t.Error("Resolve() with -H not-a-header returned nil error, want error")
	}
}

func TestResolveDefaultsToNoHeaders(t *testing.T) {
	cfg, _, err := config.Resolve(nil, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if len(cfg.Headers) != 0 {
		t.Errorf("Headers = %v, want empty", cfg.Headers)
	}
}

func TestResolveDefaultsToExposedPathsDisabled(t *testing.T) {
	cfg, _, err := config.Resolve(nil, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = true, want false by default")
	}
	if len(cfg.ExtraExposedPaths) != 0 {
		t.Errorf("ExtraExposedPaths = %v, want empty by default", cfg.ExtraExposedPaths)
	}
}

func TestResolveCheckExposedPathsFlag(t *testing.T) {
	cfg, _, err := config.Resolve([]string{"-check-exposed-paths"}, noEnv)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if !cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = false, want true from -check-exposed-paths")
	}
}

func TestResolveCheckExposedPathsEnvVar(t *testing.T) {
	cfg, _, err := config.Resolve(nil, envWith(map[string]string{"MAMORI_CHECK_EXPOSED_PATHS": "true"}))
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if !cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = false, want true from MAMORI_CHECK_EXPOSED_PATHS")
	}
}

func TestResolveCheckExposedPathsFlagOverridesEnvVar(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-check-exposed-paths=false"},
		envWith(map[string]string{"MAMORI_CHECK_EXPOSED_PATHS": "true"}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = true, want false: -check-exposed-paths=false overriding MAMORI_CHECK_EXPOSED_PATHS=true")
	}
}

func TestResolveRejectsInvalidCheckExposedPathsEnvVar(t *testing.T) {
	if _, _, err := config.Resolve(nil, envWith(map[string]string{"MAMORI_CHECK_EXPOSED_PATHS": "sure"})); err == nil {
		t.Error("Resolve() with MAMORI_CHECK_EXPOSED_PATHS=sure returned nil error, want error")
	}
}

func TestResolveParsesRepeatableExposedPathFlag(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-exposed-path", "debug.log", "-exposed-path", "old-backup.sql"},
		noEnv,
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	want := []string{"debug.log", "old-backup.sql"}
	if !reflect.DeepEqual([]string(cfg.ExtraExposedPaths), want) {
		t.Errorf("ExtraExposedPaths = %v, want %v", cfg.ExtraExposedPaths, want)
	}
	if cfg.CheckExposedPaths {
		t.Error("CheckExposedPaths = true, want false: -exposed-path alone doesn't set the boolean flag itself (PathCheckersFor is what treats it as enabling)")
	}
}

func TestResolveFailOnNoneFlagOverridesEnv(t *testing.T) {
	cfg, _, err := config.Resolve(
		[]string{"-fail-on", "none"},
		envWith(map[string]string{"MAMORI_FAIL_ON": "low"}),
	)
	if err != nil {
		t.Fatalf("Resolve() returned error: %v", err)
	}
	if cfg.FailOn != "" {
		t.Errorf("FailOn = %q, want zero value (\"none\") from -fail-on none", cfg.FailOn)
	}
}
