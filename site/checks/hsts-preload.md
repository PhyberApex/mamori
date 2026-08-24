---
layout: page
title: Strict-Transport-Security (preload)
permalink: /checks/hsts-preload
---

**Severity:** low

## What it does

Checks whether a functional `Strict-Transport-Security` header is also eligible for browsers' built-in HSTS preload lists, which enforce HTTPS on a domain from a user's very first connection — before it has ever sent that domain an HSTS header at all.

## Expected value

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `includeSubDomains` — applies the policy to all subdomains too.
- `preload` — signals opt-in submission to the [HSTS preload list](https://hstspreload.org/).

## What mamori checks

This check only runs once the [`Strict-Transport-Security`](strict-transport-security) check already passes (a valid, positive `max-age`) — a missing or self-defeating header is that check's finding to make, not this one's. Given a passing header, a value missing `includeSubDomains` or `preload` is reported as a low-severity `WEAK` finding under a distinct `Strict-Transport-Security (preload)` label, so it doesn't collide with the base HSTS finding in the same report.

## Further reading

- [hstspreload.org](https://hstspreload.org/)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [OWASP: HTTP Strict Transport Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
