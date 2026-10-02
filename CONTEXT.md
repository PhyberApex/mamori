# mamori

A concurrent scanner that checks HTTP(S) endpoints for missing or misconfigured security headers.

## Language

**Checker**:
A single rule that judges one response — its headers, or (for Transport) the scheme it arrived over — and produces zero or more Findings.
_Avoid_: Rule, Validator, Inspector.

**Finding**:
The result of running one Checker against one target — a Status, a Severity, a reference link, and (when the Status is `weak`, `exposed`, or `insecure`) a message explaining what's wrong. Its `header` field names the specific thing being reported on: a header name for a Checker/BodyChecker Finding, the literal `Transport` for a Transport Finding, or the probed path (e.g. `.git/config`) for a PathChecker Finding — reused rather than adding a path-specific field, so every reporter renders every kind through the same field.
_Avoid_: Result, Issue, Violation.

**Final URL**:
The URL of the response a Finding was actually judged on, when redirects made it differ from the target the user typed. A Finding stays keyed by the typed target; the Final URL is reported alongside it only when the two differ, so a reader can see that `https://a` was judged on `https://b/login`. PathChecker Findings never carry one: a path probe is a separate request to the target's origin, and its Finding already names the probed path.
_Avoid_: Redirect target, Effective URL — Final URL names the end of the chain that was judged, the same response Applicable and Transport are judged against.

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
A config-file entry that marks a Finding as a known false positive or accepted risk rather than a real problem, by an optional `header` and/or `host` (either may be omitted to mean "any"), matched case-insensitively as an exact string — no glob/wildcard support. A suppressed Finding is excluded from `-fail-on` gating but stays visible in output, tagged rather than deleted, so a reader can still see what was suppressed and why. The why is the Suppression's optional `reason`, rendered next to the tag in every output format. An optional `expires` date (`YYYY-MM-DD`) bounds how long the risk stays accepted: the Suppression still applies on that day and stops matching once the day is over in UTC, at which point the Finding gates again and mamori names the expired Suppression on stderr.
_Avoid_: Ignore rule, Allowlist entry — "allowlist" implies default-deny semantics mamori doesn't have; "Rule" is already avoided elsewhere in this glossary for a different concept (Checker).

**Baseline**:
A saved earlier scan — plain `-o json` output, no dedicated format — passed back with `-baseline` so `-fail-on` gates only on what changed since. It exempts Findings from the gate and does nothing else: a Finding in the Baseline that no longer appears is not reported.
_Avoid_: Snapshot, Allowlist — a Baseline records what a scan found, not what is permitted; accepting a risk on purpose is a Suppression.

**Known**:
A Finding that was already present in the Baseline, matched on target URL, `header` and Status — Severity and message are not compared, so a Finding that moves from `missing` to `weak` is new, while a reworded message is not. A Known Finding is excluded from `-fail-on` gating but stays visible in output, tagged rather than deleted. Known is independent of Suppression: a Finding can be both, either one exempts it, and both tags are rendered.
_Avoid_: Baselined, Existing, Old — Known says what the reader needs (this was already there last time) without implying it is accepted, which is what a Suppression is for.

**Hook**:
A user-supplied shell command mamori runs once per whole scan invocation — not per target — for side effects outside its own request/response cycle, e.g. disabling a WAF before scanning and re-enabling it after. `PreScanHook` runs before any target is scanned and aborts the scan if it fails; `PostScanHook` runs after the scan completes regardless of the scan's own outcome, as long as `PreScanHook` succeeded or wasn't configured. Both are bound by their own `HookTimeout`, distinct from the per-request `Timeout`.
_Avoid_: Plugin, Callback — a Hook is a single, user-owned command mamori shells out to, not an in-process extension point.

**Rate**:
The most requests per second mamori sends to any one host, evenly spaced with no burst, counting every request of a scan — the scan request, the CORS probe and each PathChecker probe. Unset means unlimited. Time spent waiting for the Rate does not count against the per-request `Timeout`, so a low Rate slows a scan down but never turns a queued request into an `error` Finding.
_Avoid_: Throttle, Delay — Rate is a ceiling per host, not a pause between requests; Workers bounds how many targets are in flight, not how fast one host is hit.

**X-XSS-Protection** (inverted pass/weak logic):
Most Checkers treat "header present with a strong value" as `pass` and "absent" as `missing` — more of the header is better. XSSProtectionChecker inverts this: the header controls a legacy browser XSS filter that current browsers have removed (Chrome 78+, Edge) or never implemented (Firefox), and *enabling* it is itself a documented exploit vector (e.g. `mode=block` as an XS-Leak side-channel) on browsers that still honor it. So `pass` is exactly `X-XSS-Protection: 0` (explicit disable); any enabled value (`1`, `1; mode=block`, `1; report=<URI>`) or unrecognized value is `weak`; absence is `missing` (low severity — nudges toward the unambiguous `0` rather than trusting browser defaults). Before assuming a new Checker follows the "more is better" pattern, check whether the header's current best-practice guidance has shifted like this one has.
_Avoid_: treating this as a template for other legacy headers without checking their own current guidance first — the inversion is specific to this header's history, not a general rule.

**Applicable**:
Whether a header can have any effect on the response the scanner actually received (after redirects), not the URL the user typed — judged by that response's Transport and by whether it is a Document. HSTS is not applicable over plain HTTP because browsers must ignore it there. Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Permissions-Policy, X-XSS-Protection and Referrer-Policy are not applicable to a response that is not a Document, because they only govern how a browser treats a page. Content-Security-Policy and X-Frame-Options stay applicable to every response, since an API is still expected to forbid framing. A Checker whose header is not applicable produces no Finding at all, since neither `pass` nor `missing` would be true. Applicable is a fact about the response, so no setting overrides it (see ADR-0001).
_Avoid_: Skipped, Ignored — those suggest the scanner chose not to look; the header simply cannot matter on that response.

**Document**:
A response a browser would render as a page: one whose `Content-Type` is `text/html` or `application/xhtml+xml`, or that declares no `Content-Type` at all — an undeclared type is treated as a Document so no Checker is silently dropped. Any other declared type (e.g. `application/json`) is not a Document.
_Avoid_: Page, HTML response — a Document is defined by the declared type, not by what the body contains; Sensitive endpoint — mamori judges what a response declares, never how sensitive its content might be.

**Transport**:
The scheme of the response the scanner actually judged, after redirects — the same response Applicable is judged against. `https` is `pass`; `http` is `insecure`, whether the target was typed as `http://` or was redirected down from `https://`. Only the final response counts: a redirect chain that passes through plain HTTP but ends on HTTPS is not judged. A target deliberately served over plain HTTP (e.g. a local dev server) is marked with a Suppression on `Transport`, not exempted.
_Avoid_: Downgrade — names only one of the two ways a response ends up on plain HTTP; Scheme — names the mechanism, not the security property.

**Insecure**:
A Status for a Transport Finding whose response arrived over plain HTTP. Kept distinct from `missing`/`weak`, which describe header state, and `exposed`, which describes a probed path — none of them fit a response whose whole transport provides no protection.
_Avoid_: Plaintext, Unencrypted — describe the symptom rather than naming the problem in the same register as `weak`/`exposed`.
