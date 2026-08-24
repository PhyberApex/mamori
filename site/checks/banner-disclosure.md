---
layout: page
title: Banner Disclosure
permalink: /checks/banner-disclosure
---

**Severity:** low

## What it does

Checks the `Server` and `X-Powered-By` headers, which exist only to advertise the backend software (and often its version) handling the request. Unlike the other checks, presence — not absence — is the problem: this information helps an attacker fingerprint the stack and target known vulnerabilities for it.

## Expected value

Neither header should be sent at all:

```
Server:
X-Powered-By:
```

## What mamori checks

Whether `Server` or `X-Powered-By` carries a non-empty value. A response with neither header produces no findings — absence is the desired state, so there's nothing to report. A present, non-empty value on either header is reported as a low-severity `WEAK` finding; a response can produce up to two findings, one per header.

## Further reading

- [MDN: Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)
- [OWASP: HTTP Headers Cheat Sheet — Server](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server)
- [OWASP: HTTP Headers Cheat Sheet — X-Powered-By](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by)
