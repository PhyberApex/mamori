---
layout: page
title: Mixed Content
permalink: /checks/mixed-content
---

**Severity:** medium

## What it does

For `https://` targets, checks the response body for resources — images, scripts, stylesheets, iframes, audio, and video — loaded over plain `http://` instead of `https://`. Those resources bypass TLS entirely, so a network attacker can tamper with or substitute them even though the page itself was served securely: the padlock in the address bar doesn't cover them.

## Expected value

Every resource an `https://` page loads should also use `https://`, or a scheme-relative URL that inherits the page's own scheme:

```html
<img src="https://example.com/logo.png">
<img src="//example.com/logo.png">
```

## What mamori checks

Fetches and parses the response body with Go's HTML parser, then inspects the `src`/`href` attribute of every `img`, `script`, `link`, `iframe`, `audio`, and `video` tag, for `https://` targets only — an `http://` target has no TLS guarantee for mixed content to undermine. For `link`, only `rel` values the browser actually fetches count (`stylesheet`, `icon`, `apple-touch-icon`, `apple-touch-icon-precomposed`, `manifest`, `preload`, `prefetch`, `prerender`) — metadata-only relations like `canonical` or `alternate` are never dereferenced, so flagging them would be a false positive. Each reference that resolves to `http://` is reported as a medium-severity `WEAK` finding; a page can produce multiple findings, one per insecure reference. A page with no insecure references produces no findings — there's no `PASS` case, mirroring how the banner disclosure check treats absence as the desired state.

## Further reading

- [MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)
