---
status: accepted
---

# Per-target grade from the worst gating Finding

A reader scanning many targets in the terminal report has to read every line to see which need attention (#57 asked for a scoring rubric and was closed pending a product decision). We decided the terminal report shows a Grade on each target's header line, after the URL: `https://example.com  grade D`.

The Grade comes only from Findings that gate: Status not `pass`, not Suppressed, not Known — the two exemptions that already define what the reader has accepted, so a suppressed `high` does not drag the Grade down. The rubric is the highest Severity among gating Findings: none → `A`, `low` → `B`, `medium` → `C`, `high` → `D`. A target with any `error` Finding gets no Grade, since nothing was judged. The letter is coloured like `statusTag` (`A` green, `B`/`C` yellow, `D` red; plain when colour is off). The summary line is unchanged.

## Considered Options

- **A numeric score or an `F` grade.** Rejected: four buckets map one-to-one onto the three Severity tiers plus clean, so the Grade is always explainable from the lines beneath it; a weighted score is not.
- **Grade every non-pass Finding, including Suppressed and Known.** Rejected: it contradicts the exemptions the gate already honours.
- **Emit the Grade in JSON/SARIF.** Rejected: NDJSON is one Finding per line, so a per-target record would break every consumer; the Grade is derivable from the Findings.
- **Grade a target that has an `error` Finding by its other Findings.** Rejected: a partial scan would read as a clean bill of health.

## Consequences

- JSON and SARIF output are byte-identical to before.
- The rubric reuses `Finding.Fails`, so any change to the gating rule changes the Grade with it.
