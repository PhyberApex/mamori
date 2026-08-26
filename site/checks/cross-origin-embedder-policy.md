---
layout: page
title: Cross-Origin-Embedder-Policy
permalink: /checks/cross-origin-embedder-policy
---

**Severity:** low

## What it does

Controls whether this page can load cross-origin resources (images, scripts, iframes, etc.) that haven't explicitly opted in via CORP or CORS. Requiring that opt-in is a prerequisite for cross-origin isolation, which unlocks powerful APIs like `SharedArrayBuffer` and gives stronger protection against Spectre-style side-channel attacks.

## Expected value

```
Cross-Origin-Embedder-Policy: require-corp
```

or

```
Cross-Origin-Embedder-Policy: credentialless
```

- `require-corp` — every cross-origin resource must set a CORP or CORS header explicitly allowing this page to load it. Safest option.
- `credentialless` — cross-origin resources load without credentials unless they opt in via CORP; less disruptive than `require-corp` since it doesn't require existing resources to add a header, at the cost of stripping cookies/auth from those requests.

## What mamori checks

Presence of the header, and that its value is one of the two values that actually require cross-origin resources to opt in. A missing header, or a present header set to `unsafe-none` — the default, which lets this page load any cross-origin resource without that resource opting in — or any other unrecognized value, is reported as `WEAK`.

Unlike mamori's other Cross-Origin-* checks, this finding is reported at low severity: leaving this header unset is often the deliberate, correct choice, since enabling it breaks embedding of any cross-origin resource that isn't itself CORP/CORS-compliant.

## Further reading

- [MDN: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
