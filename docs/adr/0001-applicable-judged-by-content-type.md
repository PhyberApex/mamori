---
status: accepted
---

# Applicable is judged by the response's declared content type

mamori is used against JSON APIs as well as pages, and a Checker for a header that only governs how a browser treats a page reported `missing` on responses where the header could protect nothing. We decided that Applicable covers what the response is as well as its Transport: Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Permissions-Policy, X-XSS-Protection and Referrer-Policy produce no Finding on a response that is not a Document, where a Document is a response declaring `text/html` or `application/xhtml+xml`, or declaring no `Content-Type` at all.

## Considered Options

- **Guess which endpoints are sensitive** (the shape #44 asked for). Rejected: mamori has no signal for sensitivity beyond what a response declares, and a guess would make Findings unexplainable.
- **Let the user pick a profile or a flag** that turns document-only Checkers off, or forces them all on. Rejected: Applicable is a fact about the response, not a preference, and the same scan often mixes pages and API endpoints.
- **Treat every document header as not applicable, including Content-Security-Policy and X-Frame-Options.** Rejected: OWASP's REST guidance asks APIs to send `frame-ancestors 'none'` and `X-Frame-Options: DENY`, so both stay applicable to every response.
- **Treat a missing `Content-Type` as not a Document.** Rejected: a response that declares nothing would silently lose five Checkers; only a positively declared non-document type narrows the scan.

## Consequences

- A Checker already receives the response headers, so it reads `Content-Type` itself; the Checker interface does not change.
- There is no setting that runs every Checker regardless of content type. A need for one is a new decision, not a missing flag.
- The SRI and mixed-content BodyCheckers are unaffected: they already find nothing in a body with no markup, and the body is fetched before its type is known.
