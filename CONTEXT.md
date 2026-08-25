# mamori

A concurrent scanner that checks HTTP(S) endpoints for missing or misconfigured security headers.

## Language

**Checker**:
A single security-header rule that inspects a response's headers and produces zero or more Findings.
_Avoid_: Rule, Validator, Inspector.

**Finding**:
The result of running one Checker against one target — a header name, a Status, a Severity, a reference link, and (when the Status is `weak`) a message explaining what's wrong.
_Avoid_: Result, Issue, Violation.

**Status**:
Where a header landed after a Checker ran: `pass` (present and effective), `missing` (absent or blank), `weak` (present but a known no-op value), `error` (the scan itself failed, e.g. an unreachable target).
_Avoid_: Result, Outcome.

**Weak**:
A Status for a header that is present but whose value provides none of the protection the header exists for. Kept distinct from `missing` because "isn't set" and "set but useless" are different problems for a reader to fix.
_Avoid_: Invalid, Misconfigured — too vague; every weak value is a specific, named failure mode, not a generic complaint.

**Severity**:
How much a Checker's finding matters when it isn't `pass` — `low` / `medium` / `high`, fixed per Checker rather than computed per Finding.
_Avoid_: Priority, Risk level.

**Isolation** (Cross-Origin-Opener-Policy):
How completely a page's browsing context group is kept separate from cross-origin popups/openers it interacts with. COOPChecker treats `same-origin`, `same-origin-allow-popups`, and `noopener-allow-popups` as providing real isolation (`pass`); `unsafe-none` and any unrecognized value provide none (`weak`).
_Avoid_: Cross-origin isolation — that's a distinct, broader platform concept (requires COOP *and* COEP together to unlock things like `SharedArrayBuffer`); don't conflate the header-level Checker with the platform-level guarantee.
