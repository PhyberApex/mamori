# mamori

A concurrent API security scanner built in Go

`mamori` scans one or more HTTP(S) endpoints for missing or misconfigured
security headers (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`) and reports the findings, with each missing header linked
to guidance on how to fix it.

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
```

Full reference for every check mamori performs is available at
[phyberapex.github.io/mamori](https://phyberapex.github.io/mamori/).

### Flags

| Flag | Default | Description |
|---|---|---|
| `-workers` | `10` | number of concurrent scan workers |
| `-timeout` | `10s` | HTTP request timeout (e.g. `5s`) |
| `-o` | `terminal` | output format: `terminal` or `json` |
| `-fail-on` | `none` | exit non-zero on findings at or above this severity: `low`, `medium`, `high`, or `none` |

`-o json` emits newline-delimited JSON, one finding per line.

`-fail-on` gates the exit code on the scan's own findings, for use as a CI
check. The default, `none`, never fails — the exit code stays `0` no matter
what the scan finds. Set it to `low`, `medium`, or `high` to enable gating:
a `missing` or `weak` finding fails once its severity reaches the configured
threshold, and a finding that couldn't be scanned at all (`error`) always
fails, regardless of threshold. When the gate trips, `mamori` exits `1`
without an extra error line, since the report above has already shown which
finding is responsible.

### Environment variables

Each flag can also be set via an environment variable; CLI flags take
precedence.

| Variable | Equivalent flag |
|---|---|
| `MAMORI_WORKERS` | `-workers` |
| `MAMORI_TIMEOUT` | `-timeout` |
| `MAMORI_OUTPUT` | `-o` |
| `MAMORI_FAIL_ON` | `-fail-on` |

## License

MIT — see [LICENSE](LICENSE).
