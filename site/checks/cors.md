---
layout: page
title: CORS Misconfiguration
permalink: /checks/cors
---

**Severity:** high (reflected origin), medium (bare wildcard)

## What it does

Cross-Origin Resource Sharing (CORS) lets a server opt specific origins into reading responses a browser would otherwise block under the same-origin policy. The dangerous misconfiguration is a server that reflects back whatever `Origin` it was sent while also setting `Access-Control-Allow-Credentials: true` — that combination lets any site on the internet make an authenticated (cookie-carrying) request on a victim's behalf and read the response. Replying with a bare `*` instead of a reflected origin, still combined with credentials, is a lower-severity finding: per the Fetch spec's CORS check, a compliant browser refuses to honor a wildcard origin on a credentialed request at all, so it isn't directly exploitable the same way — but it's still a broken configuration, since non-browser HTTP clients enforce no such restriction.

## Expected value

Either don't combine credentials with an unrestricted origin:

```
Access-Control-Allow-Origin: *
```

(no `Access-Control-Allow-Credentials` — fine for public, non-authenticated APIs)

or restrict credentialed access to a specific, allow-listed origin:

```
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Credentials: true
```

## What mamori checks

Unlike the other checks, this one needs to see how the server responds to a cross-origin request, not just the plain scan request — so mamori sends one extra probe request per target carrying a synthetic `Origin` header (`https://mamori-cors-probe.invalid`). A response is flagged as a `WEAK` finding only when `Access-Control-Allow-Origin` reflects that probe origin (or is `*`) **and** `Access-Control-Allow-Credentials` is `true`: a reflected origin is high severity, a bare `*` is medium. A bare wildcard with no credentials, or a specific allow-listed origin that doesn't match the probe's, is not flagged — a response with no `Access-Control-Allow-Origin` header at all produces no finding, since there's nothing to protect.

## Further reading

- [MDN: Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)
- [OWASP: HTML5 Security Cheat Sheet — Cross Origin Resource Sharing](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing)
