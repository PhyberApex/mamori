---
layout: page
title: Sensitive Path Exposure
permalink: /checks/sensitive-path-exposure
---

**Severity:** high (`.git/*`, `.env`, `.htpasswd`, `web.config`), medium (`*.bak`/backup archives), low (`.DS_Store`) — one step lower for a `403` hit than the same path's `200`/`206` hit

## What it does

Unlike every other check mamori runs, this one doesn't inspect the response to the target URL itself — it probes each target's origin for well-known sensitive paths (version control metadata, environment files, credential stores, common backup-file patterns) and flags any that turn out to be reachable. That's a meaningfully more intrusive scan than reading headers on the URL the user actually asked for: it issues requests to paths nobody named as a target, with a higher chance of tripping a WAF/IDS and a stronger "is this authorized" question than a passive header read. **It's off by default.**

## Enabling it

Turn the category on with `-check-exposed-paths` (or `MAMORI_CHECK_EXPOSED_PATHS=true`, or `checkExposedPaths: true` in `.mamori.yaml`), which probes the built-in default path list below. `-exposed-path <path>` (repeatable; `exposedPaths:` in the config file, no environment variable equivalent) adds extra paths on top of that list — supplying at least one enables the category on its own, even without `-check-exposed-paths`. User configuration can only extend the default list, never replace or disable any of its entries.

## Default path list

| Path | Severity |
|---|---|
| `.git/config` | high |
| `.git/HEAD` | high |
| `.env` | high |
| `.htpasswd` | high |
| `web.config` | high |
| `wp-config.php.bak` | medium |
| `config.php.bak` | medium |
| `backup.zip` | medium |
| `backup.tar.gz` | medium |
| `.DS_Store` | low |

## What mamori checks

For each target with the category enabled, mamori first sends one request to a randomized, deliberately-nonexistent path at the target's origin — fresh per target, so a target can't special-case a fixed probe string. If that doesn't come back `404`, the target is treated as unreliable for this check (e.g. a soft-404/catch-all server that would make every path below look exposed regardless of whether it actually is): mamori reports a single `ERROR` finding noting the check was skipped, and probes none of the configured paths for that target.

Otherwise, every path in the effective list (default plus any extra paths) is probed concurrently, root-relative to the target's scheme+host — regardless of any path component the target URL itself has. For `https://example.com/app/`, that's `https://example.com/.git/config`, not `https://example.com/app/.git/config`.

A `200` or `206` response is a full-severity `EXPOSED` finding: the path is directly readable. A `403` is still a finding — the server treated the path differently from an unrecognized one, so its existence is confirmed — but one severity step down from the same path's `200`/`206` finding, since access is at least blocked. Any other status, in particular `404`, produces no finding at all.

## Further reading

- [OWASP Web Security Testing Guide: Test for Backup and Unreferenced Files or Applications](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Test_for_Backup_and_Unreferenced_Files_or_Applications)
