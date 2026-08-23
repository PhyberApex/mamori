---
layout: page
title: Set-Cookie
permalink: /checks/set-cookie
---

**Severity:** high (`Secure`), medium (`HttpOnly`, `SameSite`)

## What it does

Checks the flags on every cookie a response sets. These flags control whether a cookie can be sent over plain HTTP, read by JavaScript, or attached to cross-site requests — the three most common ways a cookie ends up stolen or abused for CSRF.

## Expected value

```
Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Strict
```

- `Secure` — the cookie is only ever sent over HTTPS, never in the clear over plain HTTP.
- `HttpOnly` — the cookie is invisible to client-side JavaScript, limiting what an XSS bug can steal.
- `SameSite=Strict` or `SameSite=Lax` — the cookie isn't attached to cross-site requests, mitigating CSRF.

## What mamori checks

Every `Set-Cookie` header in the response, parsed independently. A response with no cookies has nothing to protect, so no `Set-Cookie` header is not itself a finding — mamori only flags cookies that are actually present and weak.

For each cookie, mamori reports up to three independent `WEAK` findings:

- Missing `Secure` — high severity; the cookie can be sent over plain HTTP.
- Missing `HttpOnly` — medium severity; the cookie is readable by client-side JavaScript.
- Missing `SameSite`, or `SameSite=None` — medium severity; the cookie is sent on cross-site requests.

A cookie with all three set correctly (`Secure; HttpOnly; SameSite=Strict` or `SameSite=Lax`) produces no findings. Multiple cookies in the same response are each evaluated on their own merits.

## Further reading

- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
