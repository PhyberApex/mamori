---
layout: page
title: Content-Security-Policy
permalink: /checks/content-security-policy
---

# Content-Security-Policy

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

Presence of the header. A missing header is reported as a high-severity finding. mamori does not validate the CSP value — that requires understanding your application's intent.

## Further reading

- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
