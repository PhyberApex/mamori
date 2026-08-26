---
layout: home
title: mamori check reference
---

Each check mamori performs is documented here. Every finding includes a link to the relevant page so you can understand the issue and fix it without leaving your terminal.

## Checks

| Header | Severity | Reference |
|---|---|---|
| `Strict-Transport-Security` | high | [docs](checks/strict-transport-security) |
| `X-Content-Type-Options` | medium | [docs](checks/x-content-type-options) |
| `X-Frame-Options` | medium | [docs](checks/x-frame-options) |
| `Content-Security-Policy` | high | [docs](checks/content-security-policy) |
| `Referrer-Policy` | low | [docs](checks/referrer-policy) |
| `Cross-Origin-Opener-Policy` | medium | [docs](checks/cross-origin-opener-policy) |
| `Cross-Origin-Embedder-Policy` | low | [docs](checks/cross-origin-embedder-policy) |
| `Cross-Origin-Resource-Policy` | medium | [docs](checks/cross-origin-resource-policy) |
| `Set-Cookie` | high / medium | [docs](checks/set-cookie) |
| `Permissions-Policy` | medium | [docs](checks/permissions-policy) |
| `Server` / `X-Powered-By` | low | [docs](checks/banner-disclosure) |
| `Access-Control-Allow-Origin` | high | [docs](checks/cors) |
| `X-XSS-Protection` | low | [docs](checks/x-xss-protection) |
| `<script>` / `<link>` (SRI) | low | [docs](checks/subresource-integrity) |
| Mixed Content | medium | [docs](checks/mixed-content) |
| Sensitive Path Exposure (opt-in) | high / medium / low | [docs](checks/sensitive-path-exposure) |
