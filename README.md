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
| `-config` | *(none)* | path to a YAML config file |
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

### Environment variables

Each flag can also be set via an environment variable; CLI flags take
precedence.

| Variable | Equivalent flag |
|---|---|
| `MAMORI_WORKERS` | `-workers` |
| `MAMORI_TIMEOUT` | `-timeout` |
| `MAMORI_OUTPUT` | `-o` |
| `MAMORI_FAIL_ON` | `-fail-on` |
| `MAMORI_CONFIG` | `-config` |

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

## License

MIT — see [LICENSE](LICENSE).
