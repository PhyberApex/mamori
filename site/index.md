---
layout: home
title: mamori check reference
---

Each check mamori performs is documented here. Every finding includes a link to the relevant page so you can understand the issue and fix it without leaving your terminal.

## Checks

| Header | Severity | Reference |
|---|---|---|
| `Strict-Transport-Security` | high | [docs](checks/strict-transport-security) |
| `Strict-Transport-Security` (preload) | low | [docs](checks/hsts-preload) |
| `X-Content-Type-Options` | medium | [docs](checks/x-content-type-options) |
| `X-Frame-Options` | medium | [docs](checks/x-frame-options) |
| `Content-Security-Policy` | high | [docs](checks/content-security-policy) |
| `Referrer-Policy` | low | [docs](checks/referrer-policy) |
| `Set-Cookie` | high / medium | [docs](checks/set-cookie) |
| `Permissions-Policy` | medium | [docs](checks/permissions-policy) |
| `Server` / `X-Powered-By` | low | [docs](checks/banner-disclosure) |
| `<script>` / `<link>` (SRI) | low | [docs](checks/subresource-integrity) |
