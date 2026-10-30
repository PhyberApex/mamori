---
layout: page
title: TLS Protocol
permalink: /checks/tls-protocol
---

**Severity:** medium

## What it does

Reports whether an HTTPS target still accepts TLS 1.0 or TLS 1.1, both deprecated by RFC 8996. Go's HTTP client refuses to negotiate below TLS 1.2, so the scan's own request can't answer this; mamori instead makes one extra TLS handshake pinned to each legacy version against the host of the response it judged. **It's off by default**, because it issues handshakes nobody named as a target.

## Enabling it

`-check-tls-versions` (or `MAMORI_CHECK_TLS_VERSIONS=true`, or `checkTLSVersions: true` in `.mamori.yaml`).

## What mamori checks

For a target whose final (post-redirect) response arrived over HTTPS, one handshake with `TLS 1.0` as both minimum and maximum version and one with `TLS 1.1`, against that response's `host:port`. Certificate validity is not judged here (see the certificate check); only the negotiated version is.

- A legacy version completes a handshake → `INSECURE` (`TLS (protocol)`), naming each accepted version.
- Both are refused → `PASS`.
- The connection can't be established at all (connection refused, DNS failure, timeout) → one `ERROR` finding, `TLS version probe failed: ...`, and no `TLS (protocol)` finding.
- A plain-HTTP final response → no finding.

Each handshake is bound by `-timeout`, counts against `-rate` for that host, and is cancelled by an interrupt. Cipher-suite weakness is out of scope.

## Further reading

- [OWASP: Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
