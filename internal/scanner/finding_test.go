package scanner_test

import (
	"flag"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

// Severity must satisfy flag.Value so it can back a flag like -fail-on
// directly, without a config-level wrapper type.
var _ flag.Value = (*scanner.Severity)(nil)

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		name      string
		severity  scanner.Severity
		threshold scanner.Severity
		want      bool
	}{
		{"low at low", scanner.SeverityLow, scanner.SeverityLow, true},
		{"low below medium", scanner.SeverityLow, scanner.SeverityMedium, false},
		{"medium at medium", scanner.SeverityMedium, scanner.SeverityMedium, true},
		{"high above medium", scanner.SeverityHigh, scanner.SeverityMedium, true},
		{"medium below high", scanner.SeverityMedium, scanner.SeverityHigh, false},
		{"high at high", scanner.SeverityHigh, scanner.SeverityHigh, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.AtLeast(tt.threshold); got != tt.want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", tt.severity, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestSeverityStringRoundTrip(t *testing.T) {
	tests := []struct {
		severity scanner.Severity
		want     string
	}{
		{scanner.SeverityLow, "low"},
		{scanner.SeverityMedium, "medium"},
		{scanner.SeverityHigh, "high"},
		{scanner.Severity(""), "none"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeveritySetValid(t *testing.T) {
	tests := []struct {
		input string
		want  scanner.Severity
	}{
		{"low", scanner.SeverityLow},
		{"medium", scanner.SeverityMedium},
		{"high", scanner.SeverityHigh},
		{"none", scanner.Severity("")},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var s scanner.Severity
			if err := s.Set(tt.input); err != nil {
				t.Fatalf("Set(%q) returned error: %v", tt.input, err)
			}
			if s != tt.want {
				t.Errorf("Set(%q) = %q, want %q", tt.input, s, tt.want)
			}
		})
	}
}

func TestSeveritySetRejectsUnknownValue(t *testing.T) {
	var s scanner.Severity
	if err := s.Set("critical"); err == nil {
		t.Error("Set(\"critical\") returned nil error, want error")
	}
}

func TestAnyFails(t *testing.T) {
	findings := []scanner.Finding{
		{Status: scanner.StatusPass, Severity: scanner.SeverityHigh},
		{Status: scanner.StatusMissing, Severity: scanner.SeverityLow},
	}
	if scanner.AnyFails(findings, scanner.SeverityMedium) {
		t.Error("AnyFails() = true, want false: only finding below threshold")
	}
	if !scanner.AnyFails(findings, scanner.SeverityLow) {
		t.Error("AnyFails() = false, want true: low-severity missing finding at threshold")
	}
	if scanner.AnyFails(nil, scanner.SeverityLow) {
		t.Error("AnyFails(nil, ...) = true, want false: no findings to trip the gate")
	}
}

func TestFindingFails(t *testing.T) {
	tests := []struct {
		name      string
		finding   scanner.Finding
		threshold scanner.Severity
		want      bool
	}{
		{
			name:      "pass never fails",
			finding:   scanner.Finding{Status: scanner.StatusPass, Severity: scanner.SeverityHigh},
			threshold: scanner.SeverityLow,
			want:      false,
		},
		{
			name:      "missing below threshold does not fail",
			finding:   scanner.Finding{Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
			threshold: scanner.SeverityHigh,
			want:      false,
		},
		{
			name:      "missing at threshold fails",
			finding:   scanner.Finding{Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
			threshold: scanner.SeverityMedium,
			want:      true,
		},
		{
			name:      "weak above threshold fails",
			finding:   scanner.Finding{Status: scanner.StatusWeak, Severity: scanner.SeverityHigh},
			threshold: scanner.SeverityMedium,
			want:      true,
		},
		{
			name:      "error always fails regardless of severity",
			finding:   scanner.Finding{Status: scanner.StatusError, Severity: scanner.SeverityLow},
			threshold: scanner.SeverityHigh,
			want:      true,
		},
		{
			name:      "none threshold never fails, even a StatusError finding",
			finding:   scanner.Finding{Status: scanner.StatusError, Severity: scanner.SeverityHigh},
			threshold: scanner.Severity(""),
			want:      false,
		},
		{
			name:      "suppressed missing finding never fails, regardless of severity",
			finding:   scanner.Finding{Status: scanner.StatusMissing, Severity: scanner.SeverityHigh, Suppressed: true},
			threshold: scanner.SeverityLow,
			want:      false,
		},
		{
			name:      "suppressed error finding never fails",
			finding:   scanner.Finding{Status: scanner.StatusError, Severity: scanner.SeverityHigh, Suppressed: true},
			threshold: scanner.SeverityLow,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.finding.Fails(tt.threshold); got != tt.want {
				t.Errorf("Fails(%s) = %v, want %v", tt.threshold, got, tt.want)
			}
		})
	}
}
