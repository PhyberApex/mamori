---
status: accepted
---

# TLSChecker is a new category judging *tls.ConnectionState, starting with certificate expiry

mamori's existing Checker categories all judge something the standard library already hands back on every request: Checker judges headers, BodyChecker judges a fetched body, PathChecker judges a probe's status code. None of them can see the TLS connection itself — the certificate chain the server presented, or the negotiated protocol version — because `*tls.ConnectionState` isn't a header, a body, or a status code. Issue #46/#47 both stalled trying to fit certificate/protocol checks into the existing categories; this ADR resolves that fork.

We decided TLSChecker is a new category, parallel to Checker/BodyChecker/PathChecker:

```go
type TLSChecker interface {
	Check(state *tls.ConnectionState, respURL *url.URL) []Finding
}
```

`state` is the TLS connection state of the same response every other category already judges — captured from the existing scan request (`resp.TLS`, previously read and discarded) rather than issuing a dedicated request. It is nil whenever the final, post-redirect response arrived over plain HTTP, in which case every TLSChecker produces no Finding at all: TransportChecker's own Finding already covers that response, the same "no Finding when the thing being judged doesn't apply" rule Applicable (ADR-0001) established for headers.

The category ships with exactly one checker: `CertExpiryChecker`, which reads `state.PeerCertificates[0]` (the leaf — always the server's own certificate per RFC 8446 §4.4.2, the rest being intermediates) and compares its `NotAfter` to now plus a configurable threshold (`-cert-expiry-days` / `MAMORI_CERT_EXPIRY_DAYS` / `certExpiryDays`, default 30). Within the threshold produces `insecure` at `medium` severity; otherwise `pass`. It is default-on — only the threshold is configurable, no flag disables the checker itself. Its Finding's `Header` is exactly `"TLS (certificate)"`, a compound value in the same family as `"Set-Cookie: name (attr)"` (CONTEXT.md), so a later protocol-version checker's `"TLS (protocol)"` Findings suppress and baseline independently of this one.

An already-expired certificate is not a case `CertExpiryChecker` needs to handle: Go's TLS client refuses the handshake before any response comes back, so that target already surfaces as the existing `error` Finding.

## Considered Options

- **Widen `TransportChecker`/the `Checker` interface to also receive TLS state.** Rejected: `Checker.Check(headers http.Header, respURL *url.URL)` has no parameter for `*tls.ConnectionState`, and every existing Checker implementation would need a signature change for a parameter almost none of them use. `TransportChecker` stays the sole judge of scheme (http vs https); TLSChecker only ever supplements it.
- **A single `Header` value `"TLS"` covering both certificate and (future) protocol-version findings.** Rejected: `Suppression.header` and baseline/`Known` comparisons both match `header` as an exact string, so a single shared value would make it impossible to suppress or baseline a certificate finding without also suppressing a future protocol-version one, or vice versa.
- **Flag weak cipher suites in scope now, alongside protocol version.** Rejected for this pass: Go 1.22+'s client already refuses most weak cipher suites during the handshake, so there's little left for a Checker to observe; named as follow-up below rather than scoped in.

## Consequences

- `Scan` threads a `[]TLSChecker` through alongside `[]Checker`/`[]BodyChecker`/`[]PathChecker`: a parallel slice parameter and a parallel dispatch loop (`RunAllTLS`), the same shape `PathChecker` was added in.
- `doRequest`/`fetchBody` now return the response's `*tls.ConnectionState` alongside the header/URL/status code they already returned, so `scanTarget` can pass it to `RunAllTLS` without an extra request.
- TLS protocol-version (1.0/1.1) and weak-cipher-suite checks are explicit follow-up, not implemented here. Unlike certificate expiry, a protocol-version check can't be answered from the state of the scan's own request: Go's client refuses to complete a handshake below TLS 1.2 at all, so observing which legacy versions a server *would* accept needs a dedicated per-version handshake probe — a new kind of request this scanner doesn't otherwise issue, and a bigger design question than this ADR settles.
- No flag or config-file setting disables `CertExpiryChecker`; only `-cert-expiry-days` tunes its threshold.
