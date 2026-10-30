---
status: accepted
---

# Applicable may be judged by a declared frame-ancestors

ADR-0001 kept X-Frame-Options applicable to every response because an API is still expected to forbid framing. A response whose enforced `Content-Security-Policy` declares `frame-ancestors` is that response forbidding (or deliberately permitting) framing, and browsers discard X-Frame-Options whenever the directive is present (CSP3 §7.5, OWASP Clickjacking Defense Cheat Sheet). Reporting `[MISSING] X-Frame-Options` on a site sending `Content-Security-Policy: frame-ancestors 'none'` is therefore a false Finding. We decided that Applicable may also be judged by a declared `frame-ancestors`: `FrameOptionsChecker` produces no Finding on a response whose enforced `Content-Security-Policy` carries a `frame-ancestors` directive, whatever its value. ADR-0001 is amended, not contradicted: X-Frame-Options stays applicable to every response that does not already declare `frame-ancestors`.

`CSPChecker` gains a `frame-ancestors`-specific rule so the permissive case is still caught: `frame-ancestors *` is `weak` with the message "frame-ancestors allows * which permits framing from any origin, defeating clickjacking protection". It has its own branch rather than an entry in `wildcardSensitiveDirectives`, whose message is about XSS.

## Considered Options

- **Keep judging X-Frame-Options regardless.** Rejected: the header has no effect when `frame-ancestors` is present, so `missing` would not be true.
- **Withhold the Finding only for restrictive `frame-ancestors` values.** Rejected: the header is discarded whatever the value, which is exactly the Applicable rule; the permissive case belongs to CSPChecker.
- **Count `Content-Security-Policy-Report-Only`.** Rejected: it enforces nothing, so X-Frame-Options still matters.
- **A flag or setting that re-enables the Finding.** Rejected: Applicable is a fact about the response, as in ADR-0001 and ADR-0003.

## Consequences

- Applicable now has four inputs: Transport, Document, a declared `Set-Cookie`, and a declared `frame-ancestors`. The Checker interface does not change.
- A site relying on `frame-ancestors` alone is no longer reported for lacking X-Frame-Options; legacy browsers without CSP support are accepted as out of scope.
