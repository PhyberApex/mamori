---
layout: page
title: X-Content-Type-Options
permalink: /checks/x-content-type-options
---

# X-Content-Type-Options

**Severity:** medium

## What it does

Prevents browsers from MIME-sniffing a response away from the declared `Content-Type`. Without it, a browser might execute a file as JavaScript even if the server sent it as `text/plain`.

## Expected value

```
X-Content-Type-Options: nosniff
```

`nosniff` is the only valid value.

## What mamori checks

Presence of the header with the value `nosniff`. A missing or incorrect header is reported as a medium-severity finding.

## Further reading

- [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
- [OWASP: Security Headers](https://owasp.org/www-project-secure-headers/)
