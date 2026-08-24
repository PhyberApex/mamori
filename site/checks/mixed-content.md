---
layout: page
title: Mixed Content
permalink: /checks/mixed-content
---

**Severity:** medium

## What it does

For `https://` targets, fetches the response body and scans it for resources — images, scripts, stylesheets, iframes, audio, and video — loaded over plain `http://` instead of `https://`. Those resources bypass TLS entirely, so a network attacker can tamper with or substitute them even though the page itself was served securely: the padlock in the address bar doesn't cover them.

## Expected value

Every resource an `https://` page loads should also use `https://`, or a scheme-relative URL that inherits the page's own scheme:

```html
<img src="https://example.com/logo.png">
<img src="//example.com/logo.png">
```

## What mamori checks

The `src`/`href` attribute of every `img`, `script`, `link`, `iframe`, `audio`, and `video` tag in the response body, for `https://` targets only — an `http://` target has no TLS guarantee for mixed content to undermine, so it isn't checked. Only a successful (`2xx`), HTML response is scanned; an error page, redirect, or non-HTML body (JSON, binary) is skipped, since it isn't the page mamori was asked to check. For `link`, only `rel` values the browser actually fetches count (`stylesheet`, `icon`, `apple-touch-icon`, `manifest`, `preload`, `prefetch`, `prerender`) — metadata-only relations like `canonical` or `alternate` are never dereferenced, so flagging them would be a false positive. Each reference that starts with `http://` is reported as a medium-severity `WEAK` finding; a page can produce multiple findings, one per insecure reference. A page with no insecure references produces no findings — there's no `PASS` case, mirroring how the banner disclosure check treats absence as the desired state.

mamori reads at most 5MB of the response body — insecure references live in early markup, so a cap keeps a huge or slow-drip response from costing unbounded memory.

If the body can't be fetched after the header checks already succeeded (e.g. a transient failure on the follow-up request), mamori reports a single `ERROR` finding for Mixed Content rather than silently reporting zero findings, so "checked and clean" is never confused with "the check didn't run".

## Further reading

- [MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)
