---
layout: page
title: Referrer-Policy
permalink: /checks/referrer-policy
---

**Severity:** low

## What it does

Controls how much referrer information (the URL of the page the user came from) is included in requests. Without it, the full URL — including query strings containing tokens or sensitive data — can leak to third parties.

## Expected value

```
Referrer-Policy: strict-origin-when-cross-origin
```

This is the browser default since 2021 and a safe choice for most APIs. More restrictive options:

- `no-referrer` — never send referrer information.
- `same-origin` — only send referrer for same-origin requests.

## What mamori checks

Presence of the header, that it contains at least one recognized policy token, and that it isn't set to `unsafe-url`. A missing header is reported as a low-severity finding. A present header set to `unsafe-url` is reported as `WEAK` — it explicitly sends the full URL, including query strings, to third parties on every cross-origin request, the opposite of what this header is for. A value with no recognized token (e.g. a typo such as `strict-origin-when-cross-origi`) is also reported as `WEAK`: browsers ignore it and fall back to their default, so it protects exactly as little as a missing header.

## Further reading

- [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [OWASP: Security Headers](https://owasp.org/www-project-secure-headers/)
