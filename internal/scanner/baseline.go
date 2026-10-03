package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// LoadBaseline reads a previously saved scan from path — NDJSON, one Finding
// per line, exactly the format -o json already produces — for -baseline,
// MAMORI_BASELINE, or the baseline config-file key to match the current
// scan's Findings against (see ApplyBaseline). It is called once at
// config-load time (see config.Resolve), not deferred to scan time, so a
// baseline file that doesn't exist, can't be read, or doesn't parse fails
// config loading the same way an invalid -timeout value does: before any
// scanning starts. Blank lines are skipped, the same leniency a hand-edited
// or concatenated NDJSON file might need.
func LoadBaseline(path string) ([]Finding, error) {
	//nolint:gosec // G304 false positive: path is the user's own -baseline/MAMORI_BASELINE/config selection, not attacker-controlled input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var f Finding
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		findings = append(findings, f)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return findings, nil
}

// baselineKey derives the tuple ApplyBaseline matches on: plain, exact
// string equality on URL, Header, and Status. Unlike Suppression.Matches,
// there is no case-insensitivity or normalization here — both sides are
// produced by the same scanner code across runs, not user-authored config.
func baselineKey(f Finding) string {
	return f.URL + "\x00" + f.Header + "\x00" + string(f.Status)
}

// ApplyBaseline marks each Finding in findings whose Known field should be
// set, given baseline as loaded by LoadBaseline. It mutates findings in
// place, the same in-place-by-index pattern ApplySuppressions uses, and is
// independent of ApplySuppressions: this never reads or writes Suppressed,
// so call order between the two doesn't matter for correctness. A baseline
// entry with no match among findings produces no output anywhere — this
// only ever marks findings that are already present, never synthesizes one
// for an unmatched entry.
func ApplyBaseline(findings []Finding, baseline []Finding) {
	known := make(map[string]bool, len(baseline))
	for _, b := range baseline {
		known[baselineKey(b)] = true
	}
	for i := range findings {
		if known[baselineKey(findings[i])] {
			findings[i].Known = true
		}
	}
}
