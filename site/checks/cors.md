---
layout: page
title: CORS Misconfiguration
permalink: /checks/cors
---

**Severity:** high

## What it does

Cross-Origin Resource Sharing (CORS) lets a server opt specific origins into reading responses a browser would otherwise block under the same-origin policy. The dangerous misconfiguration is a server that accepts *any* origin — either by reflecting back whatever `Origin` it was sent, or replying with a bare `*` — while also setting `Access-Control-Allow-Credentials: true`. That combination lets any site on the internet make an authenticated (cookie-carrying) request on a victim's behalf and read the response.

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

Unlike the other checks, this one needs to see how the server responds to a cross-origin request, not just the plain scan request — so mamori sends one extra probe request per target carrying a synthetic `Origin` header (`https://mamori-cors-probe.invalid`). A response is flagged as a high-severity `WEAK` finding only when `Access-Control-Allow-Origin` reflects that probe origin (or is `*`) **and** `Access-Control-Allow-Credentials` is `true`. A bare wildcard with no credentials, or a specific allow-listed origin that doesn't match the probe's, is not flagged — a response with no `Access-Control-Allow-Origin` header at all produces no finding, since there's nothing to protect.

## Further reading

- [MDN: Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)
- [OWASP: HTML5 Security Cheat Sheet — Cross Origin Resource Sharing](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing)
