# mamori

A concurrent API security scanner built in Go

`mamori` scans one or more HTTP(S) endpoints for missing or misconfigured
security headers (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`, `Cross-Origin-Resource-Policy`) and reports the findings,
with each missing header linked to guidance on how to fix it.

## Install

### go install

```sh
go install github.com/PhyberApex/mamori/cmd/mamori@latest
```

### Docker

Release builds are published to GitHub Container Registry:

```sh
docker run --rm ghcr.io/phyberapex/mamori:latest https://example.com
```

### Build from source

```sh
git clone https://github.com/PhyberApex/mamori.git
cd mamori
go build ./cmd/mamori
```

## Usage

Pass one or more target URLs as arguments:

```sh
mamori https://example.com https://example.org
```

Or pipe them via stdin, one per line:

```sh
echo "https://example.com" | mamori
```

Example output:

```
https://example.com
  [MISSING] Strict-Transport-Security (high) → https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
  [PASS] X-Content-Type-Options (medium)
  [MISSING] X-Frame-Options (medium) → https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  [MISSING] Content-Security-Policy (high) → https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  [MISSING] Referrer-Policy (low) → https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy
  [MISSING] Cross-Origin-Resource-Policy (medium) → https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
```

Full reference for every check mamori performs is available at
[phyberapex.github.io/mamori](https://phyberapex.github.io/mamori/).

### Flags

| Flag | Default | Description |
|---|---|---|
| `-workers` | `10` | number of concurrent scan workers |
| `-timeout` | `10s` | HTTP request timeout (e.g. `5s`) |
| `-o` | `terminal` | output format: `terminal`, `json`, or `sarif` |
| `-fail-on` | `none` | exit non-zero on findings at or above this severity: `low`, `medium`, `high`, or `none` |
| `-H` | *(none)* | custom request header `'Key: Value'`, e.g. `-H 'Authorization: Bearer xyz'` (repeatable) |
| `-check-exposed-paths` | `false` | probe each target's origin for well-known sensitive paths (`.git`, `.env`, backups, ...) |
| `-exposed-path` | *(none)* | extra path to probe in addition to the default list (repeatable; also enables `-check-exposed-paths`) |
| `-config` | *(none)* | path to a YAML config file |
| `-pre-scan-hook` | *(none)* | shell command to run once before scanning starts; aborts the scan if it fails |
| `-post-scan-hook` | *(none)* | shell command to run once after the scan completes |
| `-hook-timeout` | `30s` | timeout for `-pre-scan-hook`/`-post-scan-hook` |
| `-v`, `-version` | `false` | print the version and exit, performing no scan |

`-o json` emits newline-delimited JSON, one finding per line.

`-o sarif` emits a [SARIF 2.1.0](https://github.com/oasis-tcs/sarif-spec) log
for GitHub code scanning / CI integration, with one result per non-pass
finding; `Severity` maps to SARIF `level` as low→`note`, medium→`warning`,
high→`error`.

`-fail-on` gates the exit code on the scan's own findings, for use as a CI
check. The default, `none`, never fails — the exit code stays `0` no matter
what the scan finds. Set it to `low`, `medium`, or `high` to enable gating:
a `missing` or `weak` finding fails once its severity reaches the configured
threshold, and a finding that couldn't be scanned at all (`error`) always
fails, regardless of threshold. When the gate trips, `mamori` exits `1`
without an extra error line, since the report above has already shown which
finding is responsible.

`-H` attaches a header to every scan request, for endpoints that require
auth (e.g. `-H 'Authorization: Bearer xyz' -H 'Cookie: session=abc'`). It
has no environment variable or config file equivalent.

`-check-exposed-paths` turns on an additional, opt-in check category: for
each target, mamori probes its origin for well-known sensitive paths
(version control metadata, `.env` files, credential stores, common backup
files) and flags any that respond `200`/`206` (readable) or `403` (exists,
but blocked). This is off by default and separate from every other check,
since it issues requests to paths the user never named as a target — a more
intrusive scan than reading headers on the URL that was actually passed in.
`-exposed-path` adds an extra path to the built-in list (repeatable) and, on
its own, also turns the category on — supplying a path can't be a silent
no-op. Before probing any configured path for a target, mamori first sends
one request to a randomized, deliberately-nonexistent path at that target's
origin; if the target doesn't answer that with `404`, it's treated as
unreliable for this check (e.g. a catch-all/soft-404 server) and mamori
reports a single error for that target instead of probing anything else.

`-pre-scan-hook` and `-post-scan-hook` let a scan trigger external side
effects — for example disabling a WAF before scanning and re-enabling it
after. Each runs once per whole invocation (not once per target), via `sh
-c`, with the resolved target list available to it as `MAMORI_HOOK_TARGETS`
(one target per line) and which phase it's running as via
`MAMORI_HOOK_PHASE` (`pre` or `post`). The hook's stdout and stderr are both
routed to mamori's own stderr, never stdout, so a hook's output can't
corrupt `-o json`/`-o sarif` output.

If `-pre-scan-hook` fails or exceeds `-hook-timeout`, the scan aborts before
any HTTP request is made and mamori exits non-zero. `-post-scan-hook` runs
after the scan completes — regardless of the scan's own findings — as long
as `-pre-scan-hook` succeeded or wasn't set, since its job (e.g. re-enabling
the WAF) needs to happen even when the scan itself failed. If
`-post-scan-hook` fails or times out, the scan's findings are still
reported normally, but mamori exits non-zero with an error distinct from a
`-fail-on` failure. With no hooks configured, no subprocess is spawned and
no hook timeout is enforced.

### Environment variables

Each flag can also be set via an environment variable; CLI flags take
precedence.

| Variable | Equivalent flag |
|---|---|
| `MAMORI_WORKERS` | `-workers` |
| `MAMORI_TIMEOUT` | `-timeout` |
| `MAMORI_OUTPUT` | `-o` |
| `MAMORI_FAIL_ON` | `-fail-on` |
| `MAMORI_CHECK_EXPOSED_PATHS` | `-check-exposed-paths` |
| `MAMORI_CONFIG` | `-config` |
| `MAMORI_PRE_SCAN_HOOK` | `-pre-scan-hook` |
| `MAMORI_POST_SCAN_HOOK` | `-post-scan-hook` |
| `MAMORI_HOOK_TIMEOUT` | `-hook-timeout` |

`-exposed-path` has no environment variable equivalent, the same as `-H`.

### Config file

Instead of passing flags and targets on every run, mamori can read them from
a YAML config file:

```yaml
workers: 5
timeout: 5s
output: json
targets:
  - https://example.com
  - https://example.org
checkExposedPaths: true
exposedPaths:
  - debug.log
suppressions:
  - header: Content-Security-Policy
    host: https://cdn.example.com
  - host: https://legacy.example.com   # header omitted -> suppresses every header for this host
preScanHook: ./disable-waf.sh
postScanHook: ./enable-waf.sh
hookTimeout: 30s
```

Select a file explicitly with `-config <path>` or `MAMORI_CONFIG=<path>`. If
neither is set, mamori looks for `.mamori.yaml` in the current directory and
uses it if present — otherwise behavior is unchanged. Targets from the config
file merge additively with any targets passed as arguments or piped via
stdin. Settings follow the same precedence as everything else: `default →
config file → environment variable → CLI flag`.

Because auto-discovery is silent, running mamori in an unfamiliar directory
that contains a `.mamori.yaml` will pick up its settings and targets without
being asked — review a directory's `.mamori.yaml` before scanning there if
you don't already trust its contents.

Each `suppressions` entry has an optional `header` and an optional `host`;
either may be omitted to mean "any" (at least one must be set). Matching is
an exact, case-insensitive string comparison against the finding's header
name and the literal target string mamori scanned — no glob/wildcard
support. A suppressed finding is excluded from `-fail-on` gating regardless
of severity, but still appears in terminal, JSON, and SARIF output, marked
as suppressed rather than omitted.

## License

MIT — see [LICENSE](LICENSE).
