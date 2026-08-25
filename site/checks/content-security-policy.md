---
layout: page
title: Content-Security-Policy
permalink: /checks/content-security-policy
---

**Severity:** high

## What it does

Tells the browser which sources of content (scripts, styles, images, etc.) are allowed to load. A well-configured CSP is one of the strongest defences against XSS attacks.

## Expected value

CSP values are highly application-specific. A minimal starting point:

```
Content-Security-Policy: default-src 'self'
```

This only allows resources from the same origin. Most apps need to expand this for fonts, analytics, CDNs, etc.

## What mamori checks

Presence of the header, and whether the value is a known no-op. A missing header is reported as a high-severity finding. A present header is flagged as weak if it:

- allows `'unsafe-inline'` in any directive, which permits inline scripts/styles and defeats CSP's XSS protection
- allows `'unsafe-eval'` in any directive, which permits string-to-code execution (`eval`, `Function`, etc.)
- allows a bare `*` source, which permits loading that content from any origin
- lacks both `object-src` and `default-src`, leaving plugin/legacy content unrestricted (`object-src` falls back to `default-src` per spec, so only missing both is a gap)

Beyond these checks, CSP values are highly application-specific — mamori does not validate the full policy against your application's intent.

## Further reading

- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
