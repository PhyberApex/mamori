---
layout: page
title: Cache-Control
permalink: /checks/cache-control
---

**Severity:** medium

## What it does

Controls whether a response may be stored by caches sitting between the origin and the client — browser cache, but also any shared proxy or CDN in the path. A response that omits `no-store`/`private` can end up cached somewhere shared, and later served to a different user. This is infrastructure-conditional rather than directly browser-exploitable: it only leaks data if a shared cache/proxy/CDN actually sits in the path.

## Expected value

```
Cache-Control: no-store
```

or

```
Cache-Control: private
```

- `no-store` — the response must not be stored by any cache. Safest option.
- `private` — the response may be stored by the browser's own cache, but not by a shared cache (proxy/CDN).

## What mamori checks

Presence of the header, and that its value contains `no-store` and/or `private` among its (comma-separated) directives. A missing header is reported as a medium-severity finding. A present header whose directives contain neither `no-store` nor `private` is reported as `WEAK` — this includes `no-cache` alone (it only forces revalidation, it doesn't prevent storage), a bare `public`, a bare `max-age=N` with no other directive, and any value with only unrecognized directives.

This checker runs unconditionally against every scanned target — mamori has no concept of endpoint sensitivity (a distinction between, say, an API response and a static asset), so it doesn't attempt to guess which targets are "sensitive" before checking.

## Further reading

- [MDN: Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
