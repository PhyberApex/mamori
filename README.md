# mamori

A concurrent API security scanner built in Go

`mamori` scans one or more HTTP(S) endpoints for missing or misconfigured
security headers (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`, `Cross-Origin-Resource-Policy`) and reports the findings,
with each missing header linked to guidance on how to fix it. HSTS is judged
only on responses received over HTTPS (after following any redirects); a
plain-HTTP response produces no finding for it, since browsers ignore the
header on that transport. The transport itself is always judged separately:
a response that lands on plain HTTP — whether the target was typed that way
or a redirect chain downgraded it from HTTPS — gets a dedicated `high`
severity `insecure` finding. `X-Frame-Options` is likewise not judged on a
response whose enforced `Content-Security-Policy` declares `frame-ancestors`,
since browsers ignore the header then; `frame-ancestors *` is flagged as a weak
CSP instead. `Permissions-Policy` is reported `weak` when it grants `camera`,
`microphone`, `geolocation`, `display-capture`, `payment` or `usb` to every
origin (a bare `*` in the allowlist); other features are never flagged.
Stack-revealing headers are reported `weak` (low severity) whenever they carry
a value: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`,
`X-Php-Version`, `X-Generator`, `X-Powered-CMS`, `X-Powered-By-Plesk`,
`X-Server-Powered-By`, `X-Umbraco-Version` and `X-Joomla-Version`, one finding
per header present. Proxy markers such as `Via`, `X-Varnish` and `X-Cache` are
not flagged.

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
https://example.com  grade D
  [MISSING] Strict-Transport-Security (high) → https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
  [PASS] X-Content-Type-Options (medium)
  [MISSING] X-Frame-Options (medium) → https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  [MISSING] Content-Security-Policy (high) → https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  [MISSING] Referrer-Policy (low) → https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy
  [MISSING] Cross-Origin-Resource-Policy (medium) → https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy

1 target · 5 missing
```

The terminal report always ends with this one-line summary: a target count,
then a clause per non-`pass` status present (`insecure`, `missing`, `weak`,
`exposed`, `error`, in that order, each omitted at a zero count), then a
`known`/`suppressed` clause tallying those two independent flags across every
finding, then — only when `-fail-on` is set to something other than `none` —
`fail-on <threshold>: passed` or `failed`, mirroring the exit-code gate
described below. Any clause with nothing to show is omitted entirely, so a
scan with no non-pass findings and no `-fail-on` prints just the target
count. `-o json` and `-o sarif` are unaffected — the summary is terminal-only.

Each target's header line also carries a letter grade (`grade A` … `grade D`)
from the highest severity among its gating findings — those that are not
`pass`, `suppressed` or `known`: none → `A`, `low` → `B`, `medium` → `C`,
`high` → `D`. A target with any `error` finding gets no grade. Like the
summary, the grade is terminal-only; JSON and SARIF are unchanged.

Full reference for every check mamori performs is available at
[phyberapex.github.io/mamori](https://phyberapex.github.io/mamori/).

### Flags

| Flag | Default | Description |
|---|---|---|
| `-workers` | `10` | number of concurrent scan workers |
| `-timeout` | `10s` | HTTP request timeout (e.g. `5s`) |
| `-rate` | `0` | max requests per second to any single host; `0` means unlimited (fractional values allowed, e.g. `0.5`) |
| `-o` | `terminal` | output format: `terminal`, `json`, or `sarif` |
| `-fail-on` | `none` | exit non-zero on findings at or above this severity: `low`, `medium`, `high`, or `none` |
| `-H` | *(none)* | custom request header `'Key: Value'`, e.g. `-H 'Authorization: Bearer xyz'` (repeatable) |
| `-check-exposed-paths` | `false` | probe each target's origin for well-known sensitive paths (`.git`, `.env`, backups, ...) |
| `-exposed-path` | *(none)* | extra path to probe in addition to the default list (repeatable; also enables `-check-exposed-paths`) |
| `-config` | *(none)* | path to a YAML config file |
| `-pre-scan-hook` | *(none)* | shell command to run once before scanning starts; aborts the scan if it fails |
| `-post-scan-hook` | *(none)* | shell command to run once after the scan completes |
| `-hook-timeout` | `30s` | timeout for `-pre-scan-hook`/`-post-scan-hook` |
| `-baseline` | *(none)* | path to a previously saved `-o json` scan (NDJSON); matching findings are marked known and exempt from `-fail-on` |
| `-cert-expiry-days` | `30` | flag a target's TLS certificate as expiring once it's within this many days of its expiry |
| `-check-tls-versions` | `false` | probe each HTTPS target's host with TLS 1.0 and TLS 1.1 handshakes and report whether it still accepts them |
| `-v`, `-version` | `false` | print the version and exit, performing no scan |

`-o json` emits newline-delimited JSON, one finding per line.

`-o sarif` emits a [SARIF 2.1.0](https://github.com/oasis-tcs/sarif-spec) log
for GitHub code scanning / CI integration, with one result per non-pass
finding; `Severity` maps to SARIF `level` as low→`note`, medium→`warning`,
high→`error`.

`-fail-on` gates the exit code on the scan's own findings, for use as a CI
check. The default, `none`, never fails — the exit code stays `0` no matter
what the scan finds. Set it to `low`, `medium`, or `high` to enable gating:
a `missing`, `weak`, `exposed`, or `insecure` finding fails once its severity
reaches the configured threshold, and a finding that couldn't be scanned at
all (`error`) always fails, regardless of threshold. When the gate trips,
`mamori` exits `1` without an extra error line, since the report above has
already shown which finding is responsible — unless a Hook also failed (see
Hooks below), in which case that takes priority and `mamori` exits `3`
instead, or the scan was interrupted (see Interrupts below), which outranks
both and exits `4`. Any other error (a bad flag, an unreadable or invalid
config file, no resolvable targets, or a failure writing the report) exits
`2`, with a "mamori: ..." stderr line describing the problem. A caller (e.g.
CI) can tell these apart from the exit code alone, without parsing stderr.

Because the transport itself is judged by default (see above), any
`http://` target — or an `https://` target that redirects down to `http://`
— now produces a `high` severity `insecure` finding, and so trips
`-fail-on high` unless suppressed. A target that's deliberately served over
plain HTTP (e.g. a local dev server) opts out with an ordinary Suppression,
`{header: "Transport"}`, same as any other accepted-risk finding — see
Config file below.

`-rate` caps how fast mamori sends requests to any single host (by the
`host:port` the request actually ends up going to, after following any
redirect — not necessarily the host in the URL you typed), evenly spacing
consecutive requests at least `1/-rate` seconds apart with no burst
allowance: the first request to a host is never delayed, and the limit is
shared across the whole scan, not reset per target, since multiple targets
can resolve to the same host. It covers every request mamori sends on a
target's behalf — the plain scan request, the CORS/Origin probe, and every
`-check-exposed-paths` probe — but not `-pre-scan-hook`/`-post-scan-hook`,
which aren't HTTP requests. The default, `0`, is unlimited and behaves
exactly as if `-rate` were never added. Time spent waiting on the limiter
never counts against `-timeout`, so a request queued behind a slow rate
can't fail with a timeout purely for having waited — `-timeout` only starts
once the limiter actually releases a request. One consequence: with `-rate`
set, `-timeout` bounds each individual request mamori sends, including each
hop of a redirect chain separately, rather than the whole chain combined —
so a target that redirects several times can take up a multiple of
`-timeout` in total, as long as no single hop exceeds it.

`-H` attaches a header to every scan request, for endpoints that require
auth (e.g. `-H 'Authorization: Bearer xyz' -H 'Cookie: session=abc'`). It
has no environment variable or config file equivalent.

Every request mamori sends — including redirect hops and
`-check-exposed-paths` probes — carries a default `User-Agent` of
`mamori/<version> (+https://github.com/PhyberApex/mamori)`, where
`<version>` is the same string `-version` prints (`dev` for a plain
`go build`/`go run`). This lets an operator allowlist mamori in a WAF or
rate limiter. `-H 'User-Agent: ...'` overrides it, same as any other header.

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

Every HTTPS target's leaf certificate is checked for expiry, on by default:
once its expiry is within `-cert-expiry-days` (default `30`) of now, the
finding (`TLS (certificate)`) is `insecure` at `medium` severity; otherwise
`pass`. Unlike `-check-exposed-paths`, there's no flag to turn this checker
off — it reads TLS state mamori already has from the scan's own request, no
extra request — only `-cert-expiry-days` tunes its threshold. A plain-HTTP
target, or one that redirects down to plain HTTP, produces no finding from
this checker at all (TransportChecker's own finding already covers it), and
an already-expired certificate never reaches it either: Go's HTTP client
refuses the handshake first, surfacing as the existing `error` finding.

`-check-tls-versions` turns on an additional, opt-in check: for each target
whose judged (final, post-redirect) response arrived over HTTPS, mamori makes
one extra TLS handshake pinned to TLS 1.0 and one pinned to TLS 1.1 against
that response's host and reports a single `TLS (protocol)` finding —
`insecure` at `medium` severity naming the legacy version(s) the server
accepted (both are deprecated by RFC 8996), or `pass` when both are refused.
It is off by default because it issues handshakes the user never asked for
on the target. Each handshake is bound by `-timeout`, counts against `-rate`
for that host, and is cancelled by an interrupt. If the connection can't be
established at all (connection refused, DNS failure, timeout) the target gets
one `error` finding, `TLS version probe failed: ...`, and no `TLS (protocol)`
finding. Certificate validity is not judged here, and cipher-suite weakness
is out of scope. See ADR-0005.

`-baseline` points at a previously saved scan — exactly `-o json`'s own
output, NDJSON, one `Finding` per line — and marks every current finding with
an exactly matching `url`, `header`, and `status` as known: `known: true` in
JSON, a `[KNOWN]` tag in terminal output, and `baselineState: "unchanged"` in
SARIF (every other non-pass SARIF result gets `"new"` instead, but only once
a baseline was actually supplied). `severity` and `message` are never
compared, so a finding that is otherwise identical but was reworded or had
its severity tuned is still known, while one whose `status` changed (e.g.
`missing` → `weak`) is not. A known finding is excluded from `-fail-on`
gating the same way a suppressed one is — independently: a finding can be
known, suppressed, both, or neither, and every applicable tag is rendered. A
baseline entry with no match in the current scan produces no output of any
kind; there's no flag to generate a baseline file, since `-o json > file.json`
already is one. With no `-baseline` supplied, output is unchanged in every
format: no `known` field, no `[KNOWN]` tag, no `baselineState` field anywhere.
A `-baseline` file that doesn't exist, can't be read, or doesn't parse as
NDJSON `Finding` records fails config loading before any scanning starts, the
same way an invalid `-timeout` does.

`-pre-scan-hook` and `-post-scan-hook` let a scan trigger external side
effects — for example disabling a WAF before scanning and re-enabling it
after. Each runs once per whole invocation (not once per target), via `sh
-c`, with the resolved target list available to it as `MAMORI_HOOK_TARGETS`
(one target per line) and which phase it's running as via
`MAMORI_HOOK_PHASE` (`pre` or `post`). The hook's stdout and stderr are both
routed to mamori's own stderr, never stdout, so a hook's output can't
corrupt `-o json`/`-o sarif` output.

If `-pre-scan-hook` fails or exceeds `-hook-timeout`, the scan aborts before
any HTTP request is made and mamori exits `3`. `-post-scan-hook` runs after
the scan completes — regardless of the scan's own findings — as long as
`-pre-scan-hook` succeeded or wasn't set, since its job (e.g. re-enabling
the WAF) needs to happen even when the scan itself failed. If
`-post-scan-hook` fails or times out, the scan's findings are still
reported normally, but mamori still exits `3`. This takes priority over
`-fail-on`: if the post-scan Hook fails or times out *and* the scan's
findings also trip `-fail-on`, mamori exits `3`, not `1` — the Hook failure
is the more unusual, actionable problem, so it isn't silently replaced by
the routine fail-on exit code. With no hooks configured, no subprocess is
spawned and no hook timeout is enforced.

Hooks need a shell (`sh`) on `PATH`. The container image
(`ghcr.io/phyberapex/mamori`, and therefore the GitHub Action) is built on
distroless and ships no shell, so hooks do not work there: a configured hook
fails with an error naming the missing `sh` and mamori exits `3`. Hooks work
when running a `mamori` binary directly on a host that has `sh`.

Sending SIGINT (e.g. Ctrl-C) or SIGTERM (e.g. from a CI runner stopping the
job) cancels every in-flight and not-yet-started request the scan itself is
making — the plain checks, the CORS/Origin probe, and every
`-check-exposed-paths` probe — so each affected target produces a single
`error` finding with the message `scan interrupted`; any target whose
request had already completed keeps its real findings untouched. The report
is still written in full, in whichever `-o` format was selected, and
`-post-scan-hook` still gets to run (bounded only by `-hook-timeout`, as
always) so a WAF `-pre-scan-hook` disabled is reliably re-enabled even when
the scan itself didn't finish. An interrupted scan exits `4`, outranking a
Hook failure or a tripped `-fail-on` gate even if either also happens on the
same run, and prints its own "mamori: ..." stderr line. A second SIGINT or
SIGTERM — most likely sent while `-post-scan-hook` is still running — kills
mamori immediately instead of being caught again. An interrupt arriving
during `-pre-scan-hook` is unaffected by any of this: it's an ordinary Hook
failure, exiting `3` as it always has.

### Environment variables

Each flag can also be set via an environment variable; CLI flags take
precedence.

| Variable | Equivalent flag |
|---|---|
| `MAMORI_WORKERS` | `-workers` |
| `MAMORI_TIMEOUT` | `-timeout` |
| `MAMORI_RATE` | `-rate` |
| `MAMORI_OUTPUT` | `-o` |
| `MAMORI_FAIL_ON` | `-fail-on` |
| `MAMORI_CHECK_EXPOSED_PATHS` | `-check-exposed-paths` |
| `MAMORI_CONFIG` | `-config` |
| `MAMORI_PRE_SCAN_HOOK` | `-pre-scan-hook` |
| `MAMORI_POST_SCAN_HOOK` | `-post-scan-hook` |
| `MAMORI_HOOK_TIMEOUT` | `-hook-timeout` |
| `MAMORI_BASELINE` | `-baseline` |
| `MAMORI_CERT_EXPIRY_DAYS` | `-cert-expiry-days` |
| `MAMORI_CHECK_TLS_VERSIONS` | `-check-tls-versions` |

`-exposed-path` has no environment variable equivalent, the same as `-H`.

### Config file

Instead of passing flags and targets on every run, mamori can read them from
a YAML config file:

```yaml
workers: 5
timeout: 5s
rate: 2
output: json
targets:
  - https://example.com
  - https://example.org
checkExposedPaths: true
exposedPaths:
  - debug.log
checkTLSVersions: true
suppressions:
  - header: Content-Security-Policy
    host: https://cdn.example.com
  - host: https://legacy.example.com
    reason: legacy app, migration tracked in JIRA-456
    expires: 2026-12-31
preScanHook: ./disable-waf.sh
postScanHook: ./enable-waf.sh
hookTimeout: 30s
baseline: ./previous-scan.json
certExpiryDays: 30
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

An entry may also set an optional `reason` and an optional `expires`, both
independent of each other and of `header`/`host`. `reason` is freeform text
shown next to the suppressed marking in every output format (SARIF's
`suppressions[].justification`), so a reader can see not just that a finding
was suppressed but why. `expires` is a `YYYY-MM-DD` date, inclusive, in
UTC: the entry still suppresses through the end of that day and stops
matching once it has passed, at which point the finding gates under
`-fail-on` again and mamori names the expired entry on stderr — so an
accepted risk gets re-reviewed instead of being accepted forever.

## GitHub Action

Run mamori as a step in a workflow and publish its findings to the
repository's Security tab, without wiring up Docker, output redirection, and
the SARIF upload step by hand:

```yaml
- uses: PhyberApex/mamori@v1.3.0
  with:
    targets: |
      https://example.com
      https://example.org
    config: .mamori.yaml
    fail-on: high
    upload-sarif: true
```

| Input | Default | Description |
|---|---|---|
| `targets` | *(none)* | one target URL per line, parsed the same way mamori parses piped stdin |
| `config` | *(none)* | path to a YAML config file, passed through as `-config` |
| `fail-on` | `none` | exit non-zero on findings at or above this severity: `low`, `medium`, `high`, or `none` |
| `upload-sarif` | `true` | upload the scan's SARIF output to GitHub code scanning |

`targets` and a `config` file's `targets` list merge additively, the same as
CLI arguments/stdin and a config file merge today.

The action runs the release image matching its own ref: `uses:
PhyberApex/mamori@v1.3.0` runs `ghcr.io/phyberapex/mamori:v1.3.0`, the ref
used verbatim — pin it to one of mamori's own `vX.Y.Z` tags.

`upload-sarif: true` (the default) requires the caller's job to grant
`security-events: write`:

```yaml
permissions:
  security-events: write
```

The action supports Linux runners only.

`preScanHook`/`postScanHook` in the action's `config` file are not supported:
the image the action runs has no shell, so a configured hook fails with exit
code `3` (see Hooks above). Run the `mamori` binary directly in a workflow
step if you need hooks.

## License

MIT — see [LICENSE](LICENSE).
