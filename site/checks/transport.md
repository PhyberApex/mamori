---
layout: page
title: Transport
permalink: /checks/transport
---

**Severity:** high

## What it does

Judges the transport itself: whether the final response a scan actually landed on — after following any redirects — arrived over HTTPS or plain HTTP. This is separate from every header check, so a plain-HTTP target still gets a finding even though `Strict-Transport-Security` isn't checked at all on that transport (browsers ignore the header outside HTTPS).

## What mamori checks

The scheme of the final response, the same one every other check judges scheme-dependent behavior against:

- Final response is `https://` → `PASS`.
- Final response is `http://` → `INSECURE`, reported at high severity. This applies whether the target was typed as `http://`, or as `https://` and a redirect chain downgraded it to `http://` along the way — either way, the response mamori actually judged travelled unencrypted.

Unlike every other check, this one doesn't read any header at all — there's no header that names which scheme a response arrived over.

## Opting out for a deliberately plain-HTTP target

A target that's intentionally served over plain HTTP (e.g. a local dev server) isn't special-cased — there's no loopback exemption or separate flag. Suppress the finding like any other accepted risk, in `.mamori.yaml`:

```yaml
suppressions:
  - header: Transport
    host: http://localhost:8080
```

The finding stays visible in the report, tagged as suppressed, but no longer trips `-fail-on`.

## Further reading

- [OWASP: Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
