---
layout: page
title: Cross-Origin-Resource-Policy
permalink: /checks/cross-origin-resource-policy
---

**Severity:** medium

## What it does

Controls which origins can load this resource (images, scripts, etc.) via no-cors cross-origin requests. Without it, other sites can embed the resource and use side channels (like Spectre) to read data that should be off-limits to them.

## Expected value

```
Cross-Origin-Resource-Policy: same-origin
```

or

```
Cross-Origin-Resource-Policy: same-site
```

- `same-origin` — only requests from the exact same origin can load the resource. Safest option.
- `same-site` — requests from the same registrable domain (including other subdomains/schemes/ports) can load the resource.

## What mamori checks

Presence of the header, and that its value is one of the two protective values the spec defines. A missing header is reported as a medium-severity finding. A present header set to `cross-origin` — which explicitly opts back out of the protection — or any other unrecognized value is reported as `WEAK`, since neither restricts which origins can load the resource.

## Further reading

- [MDN: Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [OWASP: Secure Headers](https://owasp.org/www-project-secure-headers/)
