---
layout: page
title: Permissions-Policy
permalink: /checks/permissions-policy
---

**Severity:** medium

## What it does

Lets a site opt in or out of powerful browser features (camera, microphone, geolocation, etc.) for itself and any content it embeds. Without it, embedded third-party content can use these features unless the browser's own defaults happen to block them.

## Expected value

Permissions-Policy values are application-specific. A restrictive starting point:

```
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

This denies these features to the page and any iframes it embeds. Most apps need to expand this to allow the features they actually use.

## What mamori checks

Presence of the header. A missing header is reported as a medium-severity finding. mamori does not validate the Permissions-Policy value — that requires understanding which features your application actually needs.

## Further reading

- [MDN: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
- [OWASP: Secure Headers Project](https://owasp.org/www-project-secure-headers/#permissions-policy)
