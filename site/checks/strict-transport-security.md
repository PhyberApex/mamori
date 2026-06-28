---
layout: page
title: Strict-Transport-Security
permalink: /checks/strict-transport-security
---

# Strict-Transport-Security

**Severity:** high

## What it does

Tells browsers to only connect to this site over HTTPS, even if the user types `http://`. Prevents protocol downgrade attacks and cookie hijacking over HTTP.

## Expected value

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

- `max-age` — how long (in seconds) the browser remembers to use HTTPS. Two years (`63072000`) is recommended.
- `includeSubDomains` — applies the policy to all subdomains too.

## What mamori checks

Presence of the header. A missing or empty header is reported as a high-severity finding.

## Further reading

- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [OWASP: HTTP Strict Transport Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
