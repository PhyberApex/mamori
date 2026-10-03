package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func writeBaselineFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write baseline file: %v", err)
	}
	return path
}

func TestLoadBaselineParsesNDJSONFindings(t *testing.T) {
	path := writeBaselineFile(t, `{"url":"https://a.example","header":"X-Frame-Options","status":"missing","severity":"medium"}
{"url":"https://a.example","header":"Content-Security-Policy","status":"missing","severity":"high"}
`)

	findings, err := scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline() returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	if findings[0].URL != "https://a.example" || findings[0].Header != "X-Frame-Options" {
		t.Errorf("findings[0] = %+v, want the first NDJSON line", findings[0])
	}
}

func TestLoadBaselineSkipsBlankLines(t *testing.T) {
	path := writeBaselineFile(t, "\n{\"url\":\"https://a.example\",\"header\":\"X-Frame-Options\",\"status\":\"missing\"}\n\n")

	findings, err := scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline() returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
}

func TestLoadBaselineRejectsNonexistentFile(t *testing.T) {
	if _, err := scanner.LoadBaseline(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("LoadBaseline() with a nonexistent file returned nil error, want error")
	}
}

func TestLoadBaselineRejectsMalformedJSON(t *testing.T) {
	path := writeBaselineFile(t, "not valid json\n")
	if _, err := scanner.LoadBaseline(path); err == nil {
		t.Error("LoadBaseline() with malformed JSON returned nil error, want error")
	}
}

func TestLoadBaselineRejectsJSONThatIsNotAFindingObject(t *testing.T) {
	path := writeBaselineFile(t, `["not", "an", "object"]`+"\n")
	if _, err := scanner.LoadBaseline(path); err == nil {
		t.Error("LoadBaseline() with a JSON array line returned nil error, want error")
	}
}

func TestApplyBaselineMarksExactURLHeaderStatusMatchAsKnown(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}
	baseline := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}

	scanner.ApplyBaseline(findings, baseline)

	if !findings[0].Known {
		t.Error("findings[0].Known = false, want true: exact URL+Header+Status match")
	}
}

func TestApplyBaselineLeavesUnmatchedFindingUnknown(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}
	baseline := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}

	scanner.ApplyBaseline(findings, baseline)

	if findings[0].Known {
		t.Error("findings[0].Known = true, want false: no matching baseline entry")
	}
}

func TestApplyBaselineStatusChangeIsNotKnown(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Strict-Transport-Security", Status: scanner.StatusWeak, Severity: scanner.SeverityHigh},
	}
	baseline := []scanner.Finding{
		{URL: "https://a.example", Header: "Strict-Transport-Security", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
	}

	scanner.ApplyBaseline(findings, baseline)

	if findings[0].Known {
		t.Error("findings[0].Known = true, want false: status changed from missing to weak since the baseline")
	}
}

func TestApplyBaselineSeverityOrMessageChangeIsStillKnown(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh, Message: "reworded"},
	}
	baseline := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium, Message: "original"},
	}

	scanner.ApplyBaseline(findings, baseline)

	if !findings[0].Known {
		t.Error("findings[0].Known = false, want true: only severity/message changed, URL+Header+Status match")
	}
}

func TestApplyBaselineWithNilBaselineLeavesFindingsUnknown(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing},
	}

	scanner.ApplyBaseline(findings, nil)

	if findings[0].Known {
		t.Error("findings[0].Known = true, want false: no baseline supplied")
	}
}

func TestApplyBaselineUnmatchedBaselineEntryProducesNoEffect(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing},
	}
	baseline := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing},
		{URL: "https://gone.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing},
	}

	scanner.ApplyBaseline(findings, baseline)

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: ApplyBaseline must not add entries for unmatched baseline findings", len(findings))
	}
	if !findings[0].Known {
		t.Error("findings[0].Known = false, want true")
	}
}
