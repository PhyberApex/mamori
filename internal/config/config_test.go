package config_test

import (
	"testing"
	"time"

	"github.com/PhyberApex/mamori/internal/config"
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
}

func TestResolveEnvOverridesDefaults(t *testing.T) {
	cfg, _, err := config.Resolve(nil, envWith(map[string]string{
		"MAMORI_WORKERS": "3",
		"MAMORI_TIMEOUT": "2s",
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
}

func TestResolveFlagsOverrideEnv(t *testing.T) {
	cfg, rest, err := config.Resolve(
		[]string{"-workers", "5", "-timeout", "1s", "https://a.example"},
		envWith(map[string]string{
			"MAMORI_WORKERS": "3",
			"MAMORI_TIMEOUT": "2s",
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
	if len(rest) != 1 || rest[0] != "https://a.example" {
		t.Errorf("remaining args = %v, want [https://a.example]", rest)
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
