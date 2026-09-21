# mamori

A concurrent scanner that checks HTTP(S) endpoints for missing or misconfigured security headers.

## Language

**Checker**:
A single rule that judges one response — its headers, or (for Transport) the scheme it arrived over — and produces zero or more Findings.
_Avoid_: Rule, Validator, Inspector.

**Finding**:
The result of running one Checker against one target — a Status, a Severity, a reference link, and (when the Status is `weak`, `exposed`, or `insecure`) a message explaining what's wrong. Its `header` field names the specific thing being reported on: a header name for a Checker/BodyChecker Finding, the literal `Transport` for a Transport Finding, or the probed path (e.g. `.git/config`) for a PathChecker Finding — reused rather than adding a path-specific field, so every reporter renders every kind through the same field.
_Avoid_: Result, Issue, Violation.

**Status**:
Where a Finding landed after a Checker ran: `pass` (present and effective), `missing` (absent or blank), `weak` (present but a known no-op value), `exposed` (a PathChecker's probed path was confirmed reachable), `insecure` (the judged response arrived over plain HTTP), `error` (the scan itself failed, e.g. an unreachable target).
_Avoid_: Result, Outcome.

**PathChecker**:
A checker category parallel to Checker (headers) and BodyChecker (body): declares a path to probe at a target's origin and judges the probe response's status code rather than headers or a body. Off by default and opt-in only (`-check-exposed-paths` / `MAMORI_CHECK_EXPOSED_PATHS` / `checkExposedPaths`, plus `-exposed-path` / `exposedPaths` to extend the built-in path list), since it issues requests to paths beyond the one the user named as a target. Before probing any configured path for a target, Scan sends one baseline probe to a randomized, deliberately-nonexistent path; a target that doesn't answer that with `404` is treated as unreliable for this check (a soft-404/catch-all server) and produces a single `error` Finding instead of probing anything configured.
_Avoid_: Prober — too close to OriginProber, a distinct existing mechanism (see below) that probes the *same* target URL with a synthetic header rather than a *different* path.

**Exposed**:
A Status for a PathChecker Finding whose probed path came back `200`/`206` (a full-severity hit, the path is directly readable) or `403` (still a hit — the server treated the path differently from an unrecognized one — but one severity step down, since access is at least blocked). Kept distinct from `missing`/`weak`, which both describe header state on the target URL itself, not a separate path's reachability.
_Avoid_: Found, Discovered — too generic; `exposed` names the specific problem (a sensitive path is reachable), matching how `weak` names its problem rather than using a generic "Invalid".

**Weak**:
A Status for a header that is present but whose value provides none of the protection the header exists for. Kept distinct from `missing` because "isn't set" and "set but useless" are different problems for a reader to fix.
_Avoid_: Invalid, Misconfigured — too vague; every weak value is a specific, named failure mode, not a generic complaint.

**Severity**:
How much a Checker's finding matters when it isn't `pass` — `low` / `medium` / `high`, fixed per Checker rather than computed per Finding.
_Avoid_: Priority, Risk level.

**Isolation** (Cross-Origin-Opener-Policy):
How completely a page's browsing context group is kept separate from cross-origin popups/openers it interacts with. COOPChecker treats `same-origin`, `same-origin-allow-popups`, and `noopener-allow-popups` as providing real isolation (`pass`); `unsafe-none` and any unrecognized value provide none (`weak`).
_Avoid_: Cross-origin isolation — that's a distinct, broader platform concept (requires COOP *and* COEP together to unlock things like `SharedArrayBuffer`); don't conflate the header-level Checker with the platform-level guarantee.

**Embedding** (Cross-Origin-Embedder-Policy):
Whether a page requires every cross-origin subresource it loads to explicitly opt in — via CORP or CORS — before the browser lets it through, or accepts a policy that strips credentials from such requests instead. COEPChecker treats `require-corp` and `credentialless` as providing that guarantee (`pass`); `unsafe-none` and any unrecognized value provide none (`weak`), reported at `SeverityLow` since most sites correctly leave this unset to avoid breaking uncooperative cross-origin embeds — unlike every other header this scanner checks, absence here is often the deliberate, correct choice rather than an oversight.
_Avoid_: Cross-origin isolation — see the Isolation entry's note; that's the platform-level guarantee this header only partly enables.

**Suppression**:
A config-file entry that marks a Finding as a known false positive or accepted risk rather than a real problem, by an optional `header` and/or `host` (either may be omitted to mean "any"), matched case-insensitively as an exact string — no glob/wildcard support. A suppressed Finding is excluded from `-fail-on` gating but stays visible in output, tagged rather than deleted, so a reader can still see what was suppressed and why.
_Avoid_: Ignore rule, Allowlist entry — "allowlist" implies default-deny semantics mamori doesn't have; "Rule" is already avoided elsewhere in this glossary for a different concept (Checker).

**Hook**:
A user-supplied shell command mamori runs once per whole scan invocation — not per target — for side effects outside its own request/response cycle, e.g. disabling a WAF before scanning and re-enabling it after. `PreScanHook` runs before any target is scanned and aborts the scan if it fails; `PostScanHook` runs after the scan completes regardless of the scan's own outcome, as long as `PreScanHook` succeeded or wasn't configured. Both are bound by their own `HookTimeout`, distinct from the per-request `Timeout`.
_Avoid_: Plugin, Callback — a Hook is a single, user-owned command mamori shells out to, not an in-process extension point.

**X-XSS-Protection** (inverted pass/weak logic):
Most Checkers treat "header present with a strong value" as `pass` and "absent" as `missing` — more of the header is better. XSSProtectionChecker inverts this: the header controls a legacy browser XSS filter that current browsers have removed (Chrome 78+, Edge) or never implemented (Firefox), and *enabling* it is itself a documented exploit vector (e.g. `mode=block` as an XS-Leak side-channel) on browsers that still honor it. So `pass` is exactly `X-XSS-Protection: 0` (explicit disable); any enabled value (`1`, `1; mode=block`, `1; report=<URI>`) or unrecognized value is `weak`; absence is `missing` (low severity — nudges toward the unambiguous `0` rather than trusting browser defaults). Before assuming a new Checker follows the "more is better" pattern, check whether the header's current best-practice guidance has shifted like this one has.
_Avoid_: treating this as a template for other legacy headers without checking their own current guidance first — the inversion is specific to this header's history, not a general rule.

**Applicable**:
Whether a header can have any effect for the transport the response arrived over, judged by the scheme of the response the scanner actually received (after redirects), not the URL the user typed. HSTS is not applicable over plain HTTP because browsers must ignore it there. A Checker whose header is not applicable produces no Finding at all, since neither `pass` nor `missing` would be true.
_Avoid_: Skipped, Ignored — those suggest the scanner chose not to look; the header simply cannot matter on that transport.

**Transport**:
The scheme of the response the scanner actually judged, after redirects — the same response Applicable is judged against. `https` is `pass`; `http` is `insecure`, whether the target was typed as `http://` or was redirected down from `https://`. Only the final response counts: a redirect chain that passes through plain HTTP but ends on HTTPS is not judged. A target deliberately served over plain HTTP (e.g. a local dev server) is marked with a Suppression on `Transport`, not exempted.
_Avoid_: Downgrade — names only one of the two ways a response ends up on plain HTTP; Scheme — names the mechanism, not the security property.

**Insecure**:
A Status for a Transport Finding whose response arrived over plain HTTP. Kept distinct from `missing`/`weak`, which describe header state, and `exposed`, which describes a probed path — none of them fit a response whose whole transport provides no protection.
_Avoid_: Plaintext, Unencrypted — describe the symptom rather than naming the problem in the same register as `weak`/`exposed`.
