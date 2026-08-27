package scanner_test

import (
	"net/http"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestExposureCheckerHitStatusesProduceExposedFinding(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantSeverity scanner.Severity
	}{
		{"200 is a full-severity hit", http.StatusOK, scanner.SeverityHigh},
		{"206 is a full-severity hit", http.StatusPartialContent, scanner.SeverityHigh},
		{"403 is a hit at a lower severity", http.StatusForbidden, scanner.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := scanner.NewExposureChecker(".env", scanner.SeverityHigh)
			findings := checker.CheckStatus(tt.statusCode)
			if len(findings) != 1 {
				t.Fatalf("CheckStatus(%d) returned %d findings, want 1", tt.statusCode, len(findings))
			}
			f := findings[0]
			if f.Status != scanner.StatusExposed {
				t.Errorf("Status = %q, want %q", f.Status, scanner.StatusExposed)
			}
			if f.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", f.Severity, tt.wantSeverity)
			}
			if f.Header != ".env" {
				t.Errorf("Header = %q, want the probed path %q", f.Header, ".env")
			}
			if f.Reference == "" {
				t.Error("Reference is empty, want a docs URL")
			}
			if f.Message == "" {
				t.Error("Message is empty, want an explanation of the hit")
			}
		})
	}
}

func TestExposureCheckerNonHitStatusesProduceNoFinding(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusMovedPermanently} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			checker := scanner.NewExposureChecker(".env", scanner.SeverityHigh)
			if findings := checker.CheckStatus(status); len(findings) != 0 {
				t.Errorf("CheckStatus(%d) returned %d findings, want 0", status, len(findings))
			}
		})
	}
}

func TestExposureChecker403SeverityStepsDownFromEachLevel(t *testing.T) {
	tests := []struct {
		configured scanner.Severity
		want403    scanner.Severity
	}{
		{scanner.SeverityHigh, scanner.SeverityMedium},
		{scanner.SeverityMedium, scanner.SeverityLow},
		{scanner.SeverityLow, scanner.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(string(tt.configured), func(t *testing.T) {
			checker := scanner.NewExposureChecker("x", tt.configured)
			findings := checker.CheckStatus(http.StatusForbidden)
			if len(findings) != 1 {
				t.Fatalf("CheckStatus(403) returned %d findings, want 1", len(findings))
			}
			if findings[0].Severity != tt.want403 {
				t.Errorf("403 severity for configured %q = %q, want %q", tt.configured, findings[0].Severity, tt.want403)
			}
			hit200 := checker.CheckStatus(http.StatusOK)
			if hit200[0].Severity != tt.configured {
				t.Errorf("200 severity = %q, want configured severity %q unchanged", hit200[0].Severity, tt.configured)
			}
		})
	}
}

func TestDefaultPathCheckersCoversTheTenDocumentedPaths(t *testing.T) {
	want := []string{
		".git/config", ".git/HEAD", ".env", ".DS_Store", ".htpasswd",
		"web.config", "wp-config.php.bak", "config.php.bak", "backup.zip", "backup.tar.gz",
	}
	checkers := scanner.DefaultPathCheckers()
	if len(checkers) != len(want) {
		t.Fatalf("DefaultPathCheckers() returned %d checkers, want %d", len(checkers), len(want))
	}
	got := make(map[string]bool, len(checkers))
	for _, c := range checkers {
		got[c.Path()] = true
	}
	for _, path := range want {
		if !got[path] {
			t.Errorf("DefaultPathCheckers() is missing %q", path)
		}
	}
}

func TestPathCheckersForDisabledWithNoExtraPathsReturnsNil(t *testing.T) {
	if got := scanner.PathCheckersFor(false, nil); got != nil {
		t.Errorf("PathCheckersFor(false, nil) = %v, want nil (category off)", got)
	}
}

func TestPathCheckersForEnabledReturnsDefaultList(t *testing.T) {
	checkers := scanner.PathCheckersFor(true, nil)
	if len(checkers) != len(scanner.DefaultPathCheckers()) {
		t.Errorf("PathCheckersFor(true, nil) returned %d checkers, want %d (the default list)", len(checkers), len(scanner.DefaultPathCheckers()))
	}
}

func TestPathCheckersForExtraPathAloneEnablesCategory(t *testing.T) {
	checkers := scanner.PathCheckersFor(false, []string{"debug.log"})
	if checkers == nil {
		t.Fatal("PathCheckersFor(false, [\"debug.log\"]) = nil, want the category enabled by the extra path alone")
	}
	want := len(scanner.DefaultPathCheckers()) + 1
	if len(checkers) != want {
		t.Errorf("PathCheckersFor(false, [\"debug.log\"]) returned %d checkers, want %d (default list + 1 extra)", len(checkers), want)
	}
	found := false
	for _, c := range checkers {
		if c.Path() == "debug.log" {
			found = true
		}
	}
	if !found {
		t.Error("extra path \"debug.log\" is missing from the effective checker set")
	}
}

func TestPathCheckersForExtraPathAddsToDefaultListNeverReplacesIt(t *testing.T) {
	checkers := scanner.PathCheckersFor(true, []string{"debug.log"})
	paths := map[string]bool{}
	for _, c := range checkers {
		paths[c.Path()] = true
	}
	for _, defaultPath := range []string{".git/config", ".env"} {
		if !paths[defaultPath] {
			t.Errorf("default path %q is missing when extra paths are configured, want it kept", defaultPath)
		}
	}
	if !paths["debug.log"] {
		t.Error("extra path \"debug.log\" is missing")
	}
}

func TestPathCheckersForExtraPathDuplicatingADefaultIsProbedOnce(t *testing.T) {
	checkers := scanner.PathCheckersFor(true, []string{".env"})
	count := 0
	for _, c := range checkers {
		if c.Path() == ".env" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%q appears %d times in the effective checker set, want 1 (extra path already in the default list)", ".env", count)
	}
}
