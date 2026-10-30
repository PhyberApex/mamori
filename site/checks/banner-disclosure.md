---
layout: page
title: Banner Disclosure
permalink: /checks/banner-disclosure
---

**Severity:** low

## What it does

Checks the `Server` and `X-Powered-By` headers, plus the other stack-revealing headers on the OWASP Secure Headers Project "headers to remove" list (`X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Php-Version`, `X-Generator`, `X-Powered-CMS`, `X-Powered-By-Plesk`, `X-Server-Powered-By`, `X-Umbraco-Version`, `X-Joomla-Version`), which exist only to advertise the backend software (and often its version) handling the request. Unlike the other checks, presence — not absence — is the problem: this information helps an attacker fingerprint the stack and target known vulnerabilities for it.

## Expected value

None of these headers should be sent at all:

```
Server:
X-Powered-By:
X-AspNet-Version:
X-Generator:
```

## What mamori checks

Whether any of the eleven headers above carries a non-empty value. A response with none of them produces no findings — absence is the desired state, so there's nothing to report. A present, non-empty value on any of them is reported as a low-severity `WEAK` finding, one per header. Proxy markers such as `Via`, `X-Varnish` and `X-Cache` are not checked: they reveal topology rather than software versions and have legitimate debugging uses.

## Further reading

- [MDN: Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)
- [OWASP: HTTP Headers Cheat Sheet — Server](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server)
- [OWASP: HTTP Headers Cheat Sheet — X-Powered-By](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by)
