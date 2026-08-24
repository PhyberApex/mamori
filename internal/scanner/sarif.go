package scanner

import (
	"encoding/json"
	"fmt"
	"io"
)

// sarifSchemaURI pins the exact SARIF 2.1.0 schema document these reports
// validate against, per oasis-tcs/sarif-spec.
const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// SarifReporter emits a SARIF 2.1.0 log (oasis-tcs/sarif-spec), the format
// GitHub code scanning and similar CI tooling expect. Only non-pass findings
// become results — a clean header carries no actionable location for a code
// scanning UI to annotate.
type SarifReporter struct{}

func (SarifReporter) Report(findings []Finding, w io.Writer) error {
	driver := sarifDriver{
		Name:           "mamori",
		InformationURI: "https://github.com/PhyberApex/mamori",
	}
	results := []sarifResult{}
	seenRules := map[string]bool{}

	for _, f := range findings {
		if f.Status == StatusPass {
			continue
		}
		ruleID := sarifRuleID(f)
		if !seenRules[ruleID] {
			seenRules[ruleID] = true
			driver.Rules = append(driver.Rules, sarifRule{
				ID:               ruleID,
				ShortDescription: sarifText{Text: sarifRuleDescription(f)},
			})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f),
			Message: sarifText{Text: sarifMessage(f)},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: f.URL}}},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchemaURI,
		Runs: []sarifRun{
			{Tool: sarifTool{Driver: driver}, Results: results},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifRuleID gives StatusError findings a fixed rule, since they carry no
// Header to key off of — the scan itself failed before any header check ran.
func sarifRuleID(f Finding) string {
	if f.Status == StatusError {
		return "scan-error"
	}
	return f.Header
}

func sarifRuleDescription(f Finding) string {
	if f.Status == StatusError {
		return "The scan could not complete for this target."
	}
	return fmt.Sprintf("Checks the %s response header.", f.Header)
}

// sarifMessage builds a self-contained message: a Missing/Weak finding's
// Message field is often empty (see Finding.Message), so the status and
// header are spelled out here rather than assuming the caller already knows
// what triggered the result.
func sarifMessage(f Finding) string {
	if f.Status == StatusError {
		return f.Message
	}
	msg := fmt.Sprintf("%s header is %s", f.Header, f.Status)
	if f.Message != "" {
		msg += ": " + f.Message
	}
	return msg
}

// sarifLevel maps Severity to a SARIF result level; a StatusError finding has
// no Severity of its own (the scan never got far enough to check headers) so
// it always reports as "error" — a failed scan is not merely a warning.
func sarifLevel(f Finding) string {
	if f.Status == StatusError {
		return "error"
	}
	switch f.Severity {
	case SeverityLow:
		return "note"
	case SeverityHigh:
		return "error"
	default:
		return "warning"
	}
}
