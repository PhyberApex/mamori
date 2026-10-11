---
status: accepted
---

# Applicable may be judged by a declared Set-Cookie

#44 asked for a `Cache-Control` Checker on "likely-sensitive endpoints" and was handed back because the Checker had no sensitivity signal; ADR-0001 rejects guessing sensitivity and states that mamori judges what a response declares. A response carrying at least one `Set-Cookie` header is such a declaration: it has announced itself stateful, so a cache that stores it may hand the cookie, and the body alongside it, to another user. We decided that Applicable may be judged by a declared `Set-Cookie` as well as by Transport and Document: the `Cache-Control` Checker produces a Finding only on a response carrying at least one non-blank `Set-Cookie`, and that gate replaces the Document check for this Checker, so a cookie-setting JSON API response is judged exactly like a cookie-setting page.

Once the gate passes, `no-store` is `pass`; an absent or blank `Cache-Control` is `missing`; any other value, including `private`, bare `no-cache`, `public` or `max-age` alone, is `weak`. Both `missing` and `weak` carry severity `medium`, the same tier as the HttpOnly and SameSite Findings on the cookie itself.

## Considered Options

- **Guess which endpoints are sensitive** (the shape #44 asked for). Rejected, as in ADR-0001: mamori has no signal for sensitivity beyond what a response declares.
- **Combine the cookie gate with the Document check**, judging only cookie-setting Documents. Rejected: a JSON API that sets a session cookie is exactly the response a shared cache must not store, and the `Set-Cookie` declaration already says so without needing the content type.
- **Judge `Cache-Control` on every response.** Rejected: a cookieless static asset is expected to be cacheable, and reporting `missing` on it would be the same false Finding ADR-0001 removed for document-only headers.
- **Let `private` pass.** Rejected: `private` only forbids shared caches; the browser's own cache may still store the cookie-bearing response, so only `no-store` fully prevents caching.
- **Also read `Pragma` and `Expires`.** Rejected: `Pragma` is a request directive, and RFC 9111 has `Cache-Control` override `Expires` whenever both are present, so neither can change the Status once `Cache-Control` is judged.

## Consequences

- Applicable now has three inputs: Transport, Document, and a declared `Set-Cookie`. Each Checker reads the response headers it needs, so the Checker interface does not change.
- The gate is a fact about the response, so, as with Transport and Document, no setting overrides it.
- `CookieChecker` is unaffected: it still judges the cookie's own attributes, and a response with no `Set-Cookie` still produces no cookie Finding.
