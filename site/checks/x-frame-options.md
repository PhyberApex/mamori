---
layout: page
title: X-Frame-Options
permalink: /checks/x-frame-options
---

**Severity:** medium

## What it does

Controls whether the page can be embedded in an `<iframe>`. Prevents clickjacking attacks where a malicious site overlays your page invisibly to trick users into clicking things.

## Expected value

```
X-Frame-Options: DENY
```

or

```
X-Frame-Options: SAMEORIGIN
```

- `DENY` — the page cannot be framed at all. Safest option.
- `SAMEORIGIN` — can only be framed by pages on the same origin.

## What mamori checks

Presence of the header, and that its value is one of the two the spec defines. A missing header is reported as a medium-severity finding. A present header with any value other than `DENY`/`SAMEORIGIN` (case-insensitive) — including `ALLOW-FROM`, which modern browsers ignore — is reported as `WEAK`, since it provides no clickjacking protection.

## Further reading

- [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [OWASP: Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
