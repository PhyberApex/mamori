---
layout: page
title: Cross-Origin-Opener-Policy
permalink: /checks/cross-origin-opener-policy
---

**Severity:** medium

## What it does

Controls whether cross-origin popups/openers share this page's browsing context group. Without isolation, a same-origin-but-attacker-controlled popup (or a page this one opens) can hold a reference back to `window.opener` and manipulate it, and side-channel attacks like Spectre can exploit the shared context group.

## Expected value

```
Cross-Origin-Opener-Policy: same-origin
```

or

```
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

or

```
Cross-Origin-Opener-Policy: noopener-allow-popups
```

- `same-origin` — only same-origin documents share this page's browsing context group. Safest option.
- `same-origin-allow-popups` — this page keeps its own browsing context group, but popups it opens aren't cut off from it.
- `noopener-allow-popups` — severs the opener relationship even with same-origin popups that don't also set this header.

## What mamori checks

Presence of the header, and that its value is one of the three values that actually provide isolation. A missing header is reported as a medium-severity finding. A present header set to `unsafe-none` — the default, which provides no isolation — or any other unrecognized value (e.g. `restrict-properties`, not a real COOP directive) is reported as `WEAK`.

## Further reading

- [MDN: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [OWASP: Secure Headers](https://owasp.org/www-project-secure-headers/)
