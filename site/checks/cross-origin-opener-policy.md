---
layout: page
title: Cross-Origin-Opener-Policy
permalink: /checks/cross-origin-opener-policy
---

**Severity:** medium

## What it does

Controls whether the page shares a browsing context group with cross-origin popups and windows that open it. Without isolation, a cross-origin window that opens your page can hold a reference to it (and vice versa), which cross-origin attacks like Spectre can exploit to read data across the boundary.

## Expected value

```
Cross-Origin-Opener-Policy: same-origin
```

or

```
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

- `same-origin` — full isolation; the page never shares a browsing context group with a cross-origin document. Safest option.
- `same-origin-allow-popups` — partial isolation; popups the page opens keep their own context group, but the opener relationship with the page itself is still isolated from other origins.
- `unsafe-none` — the default when the header is absent. No isolation at all.

## What mamori checks

Presence of the header, and that its value provides some isolation. A missing header is reported as a medium-severity finding. A present header set to `unsafe-none` or any unrecognized value is reported as `WEAK`, since it leaves the page unisolated — `same-origin` and `same-origin-allow-popups` are both accepted, since either is a real improvement over no isolation.

## Further reading

- [MDN: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
