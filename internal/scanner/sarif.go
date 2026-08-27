package scanner

import (
	"encoding/json"
	"fmt"
	"io"
)

// sarifSchemaURI pins the exact SARIF 2.1.0 schema document these reports
// validate against, per oasis-tcs/sarif-spec.
const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

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
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifText          `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

// sarifSuppression represents a suppressed result via SARIF's native
// per-result suppressions field (§3.28.14) rather than omitting the result
// from Results entirely.
type sarifSuppression struct {
	Kind sarifSuppressionKind `json:"kind"`
}

// sarifSuppressionKind is SARIF's closed set of suppression kinds, the same
// named-type-plus-constants pattern Status and Severity use elsewhere in
// this package. mamori only ever produces "external": a suppression
// recorded outside the tool run itself, via the config-file suppressions
// list, never something a checker discovered mid-scan ("inSource", SARIF's
// other kind, doesn't apply here).
type sarifSuppressionKind string

const sarifSuppressionExternal sarifSuppressionKind = "external"

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
		rule, result := sarifRuleAndResult(f)
		if !seenRules[rule.ID] {
			seenRules[rule.ID] = true
			driver.Rules = append(driver.Rules, rule)
		}
		results = append(results, result)
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

// sarifRuleAndResult builds the rule and result for a single non-pass
// finding. StatusError findings carry no Header/Severity of their own — the
// scan never got far enough to check headers — so they're branched on once
// here rather than in each field separately: a fixed "scan-error" rule, and
// a level of "error" since a failed scan is not merely a warning.
// StatusExposed findings reuse Header for a probed path rather than a header
// name (see Finding.Header), so they get their own wording rather than the
// "%s header is %s" phrasing every other Status shares.
func sarifRuleAndResult(f Finding) (sarifRule, sarifResult) {
	var ruleID, description, message, level string
	switch f.Status {
	case StatusError:
		ruleID = "scan-error"
		description = "The scan could not complete for this target."
		message = f.Message
		level = "error"
	case StatusExposed:
		ruleID = f.Header
		description = fmt.Sprintf("Checks whether %s is exposed.", f.Header)
		message = fmt.Sprintf("%s is exposed", f.Header)
		if f.Message != "" {
			message += ": " + f.Message
		}
		level = sarifLevel(f.Severity)
	default:
		ruleID = f.Header
		description = fmt.Sprintf("Checks the %s response header.", f.Header)
		message = fmt.Sprintf("%s header is %s", f.Header, f.Status)
		if f.Message != "" {
			message += ": " + f.Message
		}
		level = sarifLevel(f.Severity)
	}

	rule := sarifRule{ID: ruleID, ShortDescription: sarifText{Text: description}}
	result := sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifText{Text: message},
		Locations: []sarifLocation{
			{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: f.URL}}},
		},
	}
	if f.Suppressed {
		result.Suppressions = []sarifSuppression{{Kind: sarifSuppressionExternal}}
	}
	return rule, result
}

// sarifLevel maps Severity to a SARIF result level, per the low->note,
// medium->warning, high->error scheme.
func sarifLevel(s Severity) string {
	switch s {
	case SeverityLow:
		return "note"
	case SeverityHigh:
		return "error"
	default:
		return "warning"
	}
}
