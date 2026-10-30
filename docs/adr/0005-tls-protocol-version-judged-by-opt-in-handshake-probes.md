---
status: accepted
---

# TLS protocol version is judged by opt-in handshake probes, not the scan request

ADR-0002 added TLSChecker for properties of the scan request's own `*tls.ConnectionState` and named protocol-version checks as follow-up it could not answer: Go's client refuses to complete a handshake below TLS 1.2, so the scan's own connection never reveals whether a server *would* accept TLS 1.0 or 1.1. Answering it needs a dedicated per-version handshake — a new kind of outbound request.

We decided to add that as an opt-in `TLSVersionProbe`, separate from the TLSChecker category:

- Off by default; `-check-tls-versions` / `MAMORI_CHECK_TLS_VERSIONS` / `checkTLSVersions`. It issues handshakes the user did not ask for, the same reason PathChecker is opt-in.
- Target is the host:port of the Final URL (the judged response), only when that response arrived over HTTPS; a plain-HTTP response produces no Finding.
- Two handshakes per target, pinned with `MinVersion = MaxVersion` to TLS 1.0 and TLS 1.1, with `InsecureSkipVerify` and `ServerName` set. Only the negotiated version is judged; certificate validity stays CertExpiryChecker's job.
- Each handshake is bound by `-timeout`, waits on the same per-host limiter as the scan's requests (so it counts against `-rate`), and is cancelled by an interrupt, producing `scan interrupted` as path probes do.
- Outcome: a completed handshake means the version is accepted; a failed handshake (alert or protocol error) means refused; a failure to connect at all yields one `error` Finding `TLS version probe failed: <err>` and no `TLS (protocol)` Finding.
- One Finding per target, `Header` exactly `TLS (protocol)` (as ADR-0002 reserved), so it suppresses and baselines independently of `TLS (certificate)`: `insecure` at `medium` severity listing the accepted versions, `pass` when both are refused.

## Considered Options

- **Implement it as a TLSChecker.** Rejected: that interface receives an existing connection state and has no context or way to dial.
- **On by default.** Rejected: unrequested handshakes on the target.
- **A new GitHub Action input.** Rejected: the config file covers it.

## Consequences

- `Scan` takes variadic `ScanOption`s; `WithTLSVersionProbe` carries the probe, so existing callers are unchanged.
- `RateLimitedTransport.Wait` exposes its limiter so the probe shares it.
- Cipher-suite weakness remains out of scope, as ADR-0002 recorded.
