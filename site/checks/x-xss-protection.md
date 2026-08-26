---
layout: page
title: X-XSS-Protection
permalink: /checks/x-xss-protection
---

**Severity:** low

## What it does

Controlled a legacy in-browser XSS filter. Unlike every other check on this site, more of this header is *not* better: Chrome removed its XSS Auditor in Chrome 78, Edge followed, Firefox never implemented one, and WebKit has deprecated its equivalent. On the browsers that still honor it, *enabling* the filter is itself a documented exploit vector — `mode=block` in particular has been shown exploitable as an XS-Leak side-channel used to infer cross-origin state, which is the actual reason vendors removed the feature rather than leaving it as a harmless no-op.

## Expected value

```
X-XSS-Protection: 0
```

`0` explicitly disables the legacy filter. It's the only value mamori treats as safe — the goal is an unambiguous, explicit disable rather than trusting a browser's own default.

## What mamori checks

Presence of the header, and that its value is exactly `0`. A missing header is reported as a low-severity `MISSING` finding, nudging toward the explicit `0` rather than relying on browser defaults. A present header set to `1`, `1; mode=block`, `1; report=<URI>`, or any other recognized-as-enabled variant is reported as `WEAK`: enabling the filter is not a safe substitute for `0`. Any unrecognized or malformed value is also `WEAK`.

Use [Content-Security-Policy](content-security-policy) as the modern mitigation for the kind of reflected-XSS this header used to (partially, unreliably) guard against.

## Further reading

- [MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
