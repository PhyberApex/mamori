---
layout: page
title: Subresource Integrity
permalink: /checks/subresource-integrity
---

**Severity:** low

## What it does

Checks `<script src>` and `<link rel="stylesheet" href>` tags in the response body for cross-origin resources loaded without an `integrity` attribute. Subresource Integrity (SRI) lets the browser verify a fetched resource against a known hash before executing or applying it, so a compromised third-party host (e.g. a CDN) can't silently swap in malicious script or CSS.

## Expected value

Cross-origin resources should carry an `integrity` attribute with a hash of the expected content:

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

## What mamori checks

Fetches and parses the response body with Go's HTML parser, then inspects every `<script>` and `<link rel="stylesheet">` tag. A tag is flagged as a low-severity `WEAK` finding when its resource URL resolves to a different origin (scheme, host, or port) than the page itself and it has no `integrity` attribute (or a blank one). Same-origin resources are not flagged — they're served by the site itself and conventionally don't need SRI.

## Further reading

- [MDN: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [OWASP: Subresource Integrity Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Subresource_Integrity_Cheat_Sheet.html)
