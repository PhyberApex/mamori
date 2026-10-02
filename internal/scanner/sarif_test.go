package scanner_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhyberApex/mamori/internal/scanner"
)

func TestSarifReporterOmitsPassFindings(t *testing.T) {
	findings := []scanner.Finding{
		{
			URL:      "https://a.example",
			Header:   "Strict-Transport-Security",
			Status:   scanner.StatusPass,
			Severity: scanner.SeverityHigh,
		},
		{
			URL:       "https://a.example",
			Header:    "X-Frame-Options",
			Status:    scanner.StatusMissing,
			Severity:  scanner.SeverityMedium,
			Reference: "https://owasp.example/xfo",
		},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want %q", doc["version"], "2.1.0")
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want a single run", doc["runs"])
	}
	run := runs[0].(map[string]any)

	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results is not an array: %v", run["results"])
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1 (pass finding should be omitted)", len(results))
	}

	result := results[0].(map[string]any)
	if result["ruleId"] != "X-Frame-Options" {
		t.Errorf("ruleId = %v, want %q", result["ruleId"], "X-Frame-Options")
	}
}

func TestSarifReporterMapsSeverityToLevel(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Referrer-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityLow},
		{URL: "https://a.example", Header: "Permissions-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh},
		{URL: "https://down.example", Status: scanner.StatusError, Message: "context deadline exceeded"},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	levels := map[string]string{}
	for _, r := range doc.Runs[0].Results {
		levels[r.RuleID] = r.Level
	}

	want := map[string]string{
		"Referrer-Policy":         "note",
		"Permissions-Policy":      "warning",
		"Content-Security-Policy": "error",
		"scan-error":              "error",
	}
	for ruleID, wantLevel := range want {
		if levels[ruleID] != wantLevel {
			t.Errorf("level for %q = %q, want %q", ruleID, levels[ruleID], wantLevel)
		}
	}

	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "scan-error" && r.Message.Text != "context deadline exceeded" {
			t.Errorf("scan-error message = %q, want the scan error text", r.Message.Text)
		}
	}
}

func TestSarifReporterRendersExposedFindingWithoutHeaderWording(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: ".env", Status: scanner.StatusExposed, Severity: scanner.SeverityHigh, Message: "responded 200: the path is directly readable"},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("got %d results, want 1", len(doc.Runs[0].Results))
	}
	result := doc.Runs[0].Results[0]
	if result.RuleID != ".env" {
		t.Errorf("ruleId = %q, want %q", result.RuleID, ".env")
	}
	if result.Level != "error" {
		t.Errorf("level = %q, want %q (high severity)", result.Level, "error")
	}
	if strings.Contains(result.Message.Text, "header") {
		t.Errorf("message = %q, want no \"header\" wording for a path-exposure finding", result.Message.Text)
	}
	if !strings.Contains(result.Message.Text, ".env") || !strings.Contains(result.Message.Text, "responded 200") {
		t.Errorf("message = %q, want it to name the path and include the finding's own message", result.Message.Text)
	}
}

func TestSarifReporterRendersInsecureTransportFinding(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "http://a.example", Header: "Transport", Status: scanner.StatusInsecure, Severity: scanner.SeverityHigh, Message: "the response was served over plain HTTP"},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("got %d results, want 1", len(doc.Runs[0].Results))
	}
	result := doc.Runs[0].Results[0]
	if result.RuleID != "Transport" {
		t.Errorf("ruleId = %q, want %q", result.RuleID, "Transport")
	}
	if result.Level != "error" {
		t.Errorf("level = %q, want %q (high severity)", result.Level, "error")
	}
	if strings.Contains(result.Message.Text, "Transport header") {
		t.Errorf("message = %q, want no \"Transport header\" wording: Transport isn't a real response header", result.Message.Text)
	}
	if !strings.Contains(result.Message.Text, "the response was served over plain HTTP") {
		t.Errorf("message = %q, want it to include the finding's own message", result.Message.Text)
	}
}

func TestSarifReporterMarksSuppressedResultViaNativeSuppressionsField(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh, Suppressed: true},
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind string `json:"kind"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("got %d results, want 2 (suppressed finding must still appear in results)", len(doc.Runs[0].Results))
	}

	byRule := map[string][]struct {
		Kind string `json:"kind"`
	}{}
	for _, r := range doc.Runs[0].Results {
		byRule[r.RuleID] = r.Suppressions
	}

	suppressions := byRule["Content-Security-Policy"]
	if len(suppressions) != 1 || suppressions[0].Kind != "external" {
		t.Errorf("suppressed result's suppressions = %+v, want [{kind: external}]", suppressions)
	}
	if len(byRule["X-Frame-Options"]) != 0 {
		t.Errorf("non-suppressed result has suppressions = %+v, want none", byRule["X-Frame-Options"])
	}
}

func TestSarifReporterCarriesReasonAsJustificationAndOmitsItOtherwise(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Content-Security-Policy", Status: scanner.StatusMissing, Severity: scanner.SeverityHigh, Suppressed: true, SuppressedReason: "accepted risk, tracked in JIRA-123"},
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium, Suppressed: true},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	byRule := map[string][]struct {
		Kind          string `json:"kind"`
		Justification string `json:"justification"`
	}{}
	for _, r := range doc.Runs[0].Results {
		byRule[r.RuleID] = r.Suppressions
	}

	csp := byRule["Content-Security-Policy"]
	if len(csp) != 1 || csp[0].Justification != "accepted risk, tracked in JIRA-123" {
		t.Errorf("suppressed result's suppressions = %+v, want justification set to the configured reason", csp)
	}

	xfo := byRule["X-Frame-Options"]
	if len(xfo) != 1 || xfo[0].Justification != "" {
		t.Errorf("X-Frame-Options suppressions = %+v, want no justification: no reason was configured", xfo)
	}
	if strings.Count(buf.String(), "justification") != 1 {
		t.Errorf("output should contain exactly one \"justification\" key (omitted for the unreasoned suppression)\noutput:\n%s", buf.String())
	}
}

func TestSarifReporterAddsFinalURLPropertyAndOmitsItOtherwise(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "Transport", Status: scanner.StatusInsecure, Severity: scanner.SeverityHigh, FinalURL: "https://b.example/login"},
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties *struct {
					FinalURL string `json:"finalUrl"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	var transport, xfo *struct {
		RuleID    string `json:"ruleId"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
		Properties *struct {
			FinalURL string `json:"finalUrl"`
		} `json:"properties"`
	}
	for i, r := range doc.Runs[0].Results {
		switch r.RuleID {
		case "Transport":
			transport = &doc.Runs[0].Results[i]
		case "X-Frame-Options":
			xfo = &doc.Runs[0].Results[i]
		}
	}

	if transport == nil {
		t.Fatal("no Transport result found")
	}
	if uri := transport.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "https://a.example" {
		t.Errorf("Transport location URI = %q, want %q (stays the typed target)", uri, "https://a.example")
	}
	if transport.Properties == nil || transport.Properties.FinalURL != "https://b.example/login" {
		t.Errorf("Transport properties = %+v, want finalUrl %q", transport.Properties, "https://b.example/login")
	}

	if xfo == nil {
		t.Fatal("no X-Frame-Options result found")
	}
	if xfo.Properties != nil {
		t.Errorf("X-Frame-Options properties = %+v, want nil (no properties object at all)", xfo.Properties)
	}
	if strings.Count(buf.String(), "properties") != 1 {
		t.Errorf("output should contain exactly one \"properties\" key\noutput:\n%s", buf.String())
	}
}

func TestSarifReporterEnvelopeAndLocation(t *testing.T) {
	findings := []scanner.Finding{
		{URL: "https://a.example", Header: "X-Frame-Options", Status: scanner.StatusMissing, Severity: scanner.SeverityMedium},
	}

	var buf bytes.Buffer
	if err := (scanner.SarifReporter{}).Report(findings, &buf); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}

	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
	}
	if doc.Schema == "" {
		t.Error("$schema is empty, want the SARIF 2.1.0 schema URI")
	}
	if doc.Runs[0].Tool.Driver.Name != "mamori" {
		t.Errorf("tool.driver.name = %q, want %q", doc.Runs[0].Tool.Driver.Name, "mamori")
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 || doc.Runs[0].Tool.Driver.Rules[0].ID != "X-Frame-Options" {
		t.Errorf("tool.driver.rules = %+v, want a single X-Frame-Options rule", doc.Runs[0].Tool.Driver.Rules)
	}
	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if loc != "https://a.example" {
		t.Errorf("result location URI = %q, want %q", loc, "https://a.example")
	}
}
