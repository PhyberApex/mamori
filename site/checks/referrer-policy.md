---
layout: page
title: Referrer-Policy
permalink: /checks/referrer-policy
---

# Referrer-Policy

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

Presence of the header. A missing header is reported as a low-severity finding.

## Further reading

- [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [OWASP: Security Headers](https://owasp.org/www-project-secure-headers/)
