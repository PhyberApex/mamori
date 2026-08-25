---
layout: page
title: security.txt
permalink: /checks/security-txt
---

**Severity:** low

## What it does

Checks for a `security.txt` file at the well-known path defined by [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116), `/.well-known/security.txt`. It tells security researchers how to report vulnerabilities they find on your site, instead of leaving them to guess an inbox or give up.

Unlike the header checks, this probes a fixed path rather than inspecting the response already fetched for the target URL — a separate request, made against every target, whatever path was scanned.

## Expected value

A small text file at `/.well-known/security.txt`:

```
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
```

## What mamori checks

Whether `GET /.well-known/security.txt` on the target's host returns a 2xx status. The request always uses `https`, regardless of the scheme the target was scanned with — RFC 9116 §3 requires "the file access MUST use the 'https' scheme" — so a target with no HTTPS support reports as `ERROR`, not `MISSING`. Ordinary redirects are followed transparently; whatever response ultimately comes back (a 404, an unfollowed redirect, a server error) is what's judged — any final non-2xx status is reported as a low-severity `MISSING` finding. This is a well-known, publicly-intended discovery path — unlike probing for arbitrary sensitive files — so the check always runs, with no opt-in required.

## Further reading

- [RFC 9116: A File Format to Aid in Security Vulnerability Disclosure](https://www.rfc-editor.org/rfc/rfc9116)
- [securitytxt.org](https://securitytxt.org/)
