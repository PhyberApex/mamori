# Changelog

## [1.2.0](https://github.com/PhyberApex/mamori/compare/v1.1.0...v1.2.0) (2026-10-30)


### Features

* add official GitHub Action distribution ([#111](https://github.com/PhyberApex/mamori/issues/111)) ([64370d5](https://github.com/PhyberApex/mamori/commit/64370d5c3382682574ad4ce05c81748bb37ea866))
* **cli:** exit 3 for a Hook failure, taking priority over -fail-on ([#108](https://github.com/PhyberApex/mamori/issues/108)) ([221746f](https://github.com/PhyberApex/mamori/commit/221746f3268de23dcf0cab37a3582325611e7e28)), closes [#99](https://github.com/PhyberApex/mamori/issues/99)
* **config:** add pre-scan/post-scan shell command hooks ([#88](https://github.com/PhyberApex/mamori/issues/88)) ([8017dcd](https://github.com/PhyberApex/mamori/commit/8017dcd56c1c3c16f57ecfcde5094ca800612f17))
* run post-scan Hook and report partial findings on SIGINT/SIGTERM ([#124](https://github.com/PhyberApex/mamori/issues/124)) ([eefa5c4](https://github.com/PhyberApex/mamori/commit/eefa5c4c23f6471f13c093ad92d35221178774d2))
* **scanner:** -baseline flag marks recurring findings as Known ([#113](https://github.com/PhyberApex/mamori/issues/113)) ([5b8cf31](https://github.com/PhyberApex/mamori/commit/5b8cf310829a28baef0a8c9d8d3b60d3c5fad64c)), closes [#103](https://github.com/PhyberApex/mamori/issues/103)
* **scanner:** add -rate flag for per-host request throttling ([#114](https://github.com/PhyberApex/mamori/issues/114)) ([e200bab](https://github.com/PhyberApex/mamori/commit/e200bab8b54a74bbc07caefaf70a9d8b3dde109b)), closes [#104](https://github.com/PhyberApex/mamori/issues/104)
* **scanner:** add Cache-Control checker gated on a declared Set-Cookie ([#127](https://github.com/PhyberApex/mamori/issues/127)) ([efa9361](https://github.com/PhyberApex/mamori/commit/efa936115a9ee4abf895da8bdf232965f27f306d))
* **scanner:** add default-on Transport checker for plain-HTTP responses ([#97](https://github.com/PhyberApex/mamori/issues/97)) ([f1e1b98](https://github.com/PhyberApex/mamori/commit/f1e1b98874851c341a4c0633669cfc764581c92a))
* **scanner:** add one-line scan summary to terminal report ([#128](https://github.com/PhyberApex/mamori/issues/128)) ([4bc552d](https://github.com/PhyberApex/mamori/commit/4bc552dd021fc95a6ec35d7eb1bf499aa263aa7d))
* **scanner:** add opt-in sensitive-path exposure checker ([#87](https://github.com/PhyberApex/mamori/issues/87)) ([1897919](https://github.com/PhyberApex/mamori/commit/18979198e973e4497a449d3612331fd560218735))
* **scanner:** add suppressions config to mark accepted-risk Findings ([#84](https://github.com/PhyberApex/mamori/issues/84)) ([f27e67c](https://github.com/PhyberApex/mamori/commit/f27e67cd89d2ad56fd44f7fc36d595103ce00632)), closes [#59](https://github.com/PhyberApex/mamori/issues/59)
* **scanner:** add TLSChecker category with a certificate-expiry checker ([#129](https://github.com/PhyberApex/mamori/issues/129)) ([5ad2735](https://github.com/PhyberApex/mamori/commit/5ad2735d45f9c49205058d483cfb7f879534e0f5)), closes [#122](https://github.com/PhyberApex/mamori/issues/122)
* **scanner:** cover the OWASP headers-to-remove list in banner disclosure ([#172](https://github.com/PhyberApex/mamori/issues/172)) ([ae883e7](https://github.com/PhyberApex/mamori/commit/ae883e77bc5c577412a42404f730bc7bd0764b93))
* **scanner:** document-only header Checkers skip non-Document responses ([#115](https://github.com/PhyberApex/mamori/issues/115)) ([75d4f0c](https://github.com/PhyberApex/mamori/commit/75d4f0cc3da9432e301e27dac99d59150572ee1b)), closes [#105](https://github.com/PhyberApex/mamori/issues/105)
* **scanner:** Finding carries a Final Status for non-2xx judged responses ([#126](https://github.com/PhyberApex/mamori/issues/126)) ([10aa5c7](https://github.com/PhyberApex/mamori/commit/10aa5c755d22e59e4bd11d9592c5dfa445b08e5f)), closes [#119](https://github.com/PhyberApex/mamori/issues/119)
* **scanner:** Finding carries a Final URL when a redirect changed it ([#110](https://github.com/PhyberApex/mamori/issues/110)) ([71f2fb2](https://github.com/PhyberApex/mamori/commit/71f2fb29a37f00fefc11f1da186e93acd892105c))
* **scanner:** flag Permissions-Policy granting sensitive features to any origin ([#170](https://github.com/PhyberApex/mamori/issues/170)) ([f637b31](https://github.com/PhyberApex/mamori/commit/f637b31afef056c75c708a155c47507ef20f836d)), closes [#159](https://github.com/PhyberApex/mamori/issues/159)
* **scanner:** HSTS flags a max-age shorter than six months as weak ([#175](https://github.com/PhyberApex/mamori/issues/175)) ([fd2062c](https://github.com/PhyberApex/mamori/commit/fd2062c107d2ea7ae1f7a7230d528f8c4ea4dd51))
* **scanner:** HSTSChecker emits no Finding for plain-HTTP responses ([#95](https://github.com/PhyberApex/mamori/issues/95)) ([979fba6](https://github.com/PhyberApex/mamori/commit/979fba6657b3740511df98eb551f9f75e78fc786))
* **scanner:** make TerminalReporter color conditional on tty and NO_COLOR ([#107](https://github.com/PhyberApex/mamori/issues/107)) ([9356b95](https://github.com/PhyberApex/mamori/commit/9356b9567b512586155d077c9695d24e83e48f5f)), closes [#98](https://github.com/PhyberApex/mamori/issues/98)
* **scanner:** name a lone CSP Report-Only header in the missing Finding ([#171](https://github.com/PhyberApex/mamori/issues/171)) ([a9e2141](https://github.com/PhyberApex/mamori/commit/a9e2141f7b590f4ee8393c29ea1f2ca2361b158b))
* **scanner:** opt-in TLS legacy-protocol probe reports TLS 1.0/1.1 acceptance ([#173](https://github.com/PhyberApex/mamori/issues/173)) ([a9b3427](https://github.com/PhyberApex/mamori/commit/a9b342705599d592997a3982027c1e9570a384a2))
* **scanner:** send a default User-Agent on every outbound request ([#125](https://github.com/PhyberApex/mamori/issues/125)) ([e08876a](https://github.com/PhyberApex/mamori/commit/e08876a9b56cc1068ae6c013e4d80204e35888f5)), closes [#118](https://github.com/PhyberApex/mamori/issues/118)
* **scanner:** suppression carries a reason and an expiry date ([#109](https://github.com/PhyberApex/mamori/issues/109)) ([b10bfff](https://github.com/PhyberApex/mamori/commit/b10bfffd699bdbf613e838c2d6fa456fd537933f))
* **scanner:** terminal report shows a per-target grade from the worst gating Finding ([#174](https://github.com/PhyberApex/mamori/issues/174)) ([6a530db](https://github.com/PhyberApex/mamori/commit/6a530db3d9c1f1fb9f674ffebe80f0b4fac3449c))
* **scanner:** withhold X-Frame-Options finding when CSP declares frame-ancestors ([#169](https://github.com/PhyberApex/mamori/issues/169)) ([268da0d](https://github.com/PhyberApex/mamori/commit/268da0d1682cb30ba6306c3bd5ce3ff405fe6387))


### Bug Fixes

* **config:** don't load .mamori.yaml for -v/-version and -h ([#154](https://github.com/PhyberApex/mamori/issues/154)) ([f8adb87](https://github.com/PhyberApex/mamori/commit/f8adb8765114ce651da0a8b225a0115b7f5f5f7f))
* **config:** normalise and validate -exposed-path values ([#150](https://github.com/PhyberApex/mamori/issues/150)) ([7f0e550](https://github.com/PhyberApex/mamori/commit/7f0e550ad02acf9b8b55c16483380892281d7b67))
* **config:** reject -cert-expiry-days above 36500 to avoid time.Duration overflow ([#177](https://github.com/PhyberApex/mamori/issues/177)) ([7132b19](https://github.com/PhyberApex/mamori/commit/7132b19ab8cf5e800672757902c7763ec3f0af6c))
* **deps:** update module golang.org/x/net to v0.59.0 ([#90](https://github.com/PhyberApex/mamori/issues/90)) ([986673c](https://github.com/PhyberApex/mamori/commit/986673c0516bc70a917f68617de2333ac7fc212c))
* **hook:** fail with an actionable error when no sh is on PATH ([#148](https://github.com/PhyberApex/mamori/issues/148)) ([57de8d5](https://github.com/PhyberApex/mamori/commit/57de8d524bf3b15e37c21b9c7ca9874e636d8479))
* **scanner:** accept quoted max-age value in HSTS header ([#153](https://github.com/PhyberApex/mamori/issues/153)) ([3439961](https://github.com/PhyberApex/mamori/commit/34399615f1540992ee9e348b84c43e646dbdeef9))
* **scanner:** cap response body drain at 64 KiB ([#149](https://github.com/PhyberApex/mamori/issues/149)) ([3b90514](https://github.com/PhyberApex/mamori/commit/3b905146d0bba0345a92ac6e77c81a4ab73cd25a))
* **scanner:** describe insecure SARIF findings generically by Header ([#146](https://github.com/PhyberApex/mamori/issues/146)) ([562628a](https://github.com/PhyberApex/mamori/commit/562628a7580c21c6f15ee0ca33702c7a07808fc9))
* **scanner:** don't flag CSP 'unsafe-inline' beside nonce/hash or * on non-script directives ([#152](https://github.com/PhyberApex/mamori/issues/152)) ([0da3327](https://github.com/PhyberApex/mamori/commit/0da3327217a4decfb48ebe13bb3736d08db8e911))
* **scanner:** don't flag data: and blob: sources as cross-origin in SRI check ([#156](https://github.com/PhyberApex/mamori/issues/156)) ([a605a61](https://github.com/PhyberApex/mamori/commit/a605a61f0221cb092cd66f627a6273d7746003c2))
* **scanner:** emit scan interrupted finding when CORS or path probes are cancelled ([#151](https://github.com/PhyberApex/mamori/issues/151)) ([bc4b47e](https://github.com/PhyberApex/mamori/commit/bc4b47e0633d39d79539371e630daa99463d6743))
* **scanner:** give SRI, mixed-content and Set-Cookie SARIF findings stable rule ids ([#147](https://github.com/PhyberApex/mamori/issues/147)) ([f0ae673](https://github.com/PhyberApex/mamori/commit/f0ae673e55944b6cc4416a152e35d2d9c192b4c2))
* **scanner:** honour -H 'Host: ...' override ([#157](https://github.com/PhyberApex/mamori/issues/157)) ([bc1e178](https://github.com/PhyberApex/mamori/commit/bc1e1785e6180fa7022b60dea7d6cda94771db3d))
* **scanner:** judge header presence on first non-blank occurrence ([#145](https://github.com/PhyberApex/mamori/issues/145)) ([edaf463](https://github.com/PhyberApex/mamori/commit/edaf463e061835a9ec0b882b1c0920e004b3e281))
* **scanner:** mixed-content check honours upgrade-insecure-requests ([#179](https://github.com/PhyberApex/mamori/issues/179)) ([ef4d04e](https://github.com/PhyberApex/mamori/commit/ef4d04ee33fef553f788d6352c6ec9a6e53e9025))
* **scanner:** no Final URL when the typed target is only non-canonical ([#178](https://github.com/PhyberApex/mamori/issues/178)) ([3196827](https://github.com/PhyberApex/mamori/commit/3196827d9e8864bffa4441d024f1f451a7a88901))
* **scanner:** render cert-expiry threshold in days and NotAfter in UTC ([#155](https://github.com/PhyberApex/mamori/issues/155)) ([a75b6eb](https://github.com/PhyberApex/mamori/commit/a75b6ebe14ba329b1200276f2d1171ddb14a5663))
* **scanner:** report Referrer-Policy with no recognized token as weak ([#176](https://github.com/PhyberApex/mamori/issues/176)) ([39a96ef](https://github.com/PhyberApex/mamori/commit/39a96ef401a7d2ea6392108263b3f236ecfa5124))

## [1.1.0](https://github.com/PhyberApex/mamori/compare/v1.0.0...v1.1.0) (2026-08-26)


### Features

* add --version/-v flag and bug-report issue template ([#78](https://github.com/PhyberApex/mamori/issues/78)) ([e7774f3](https://github.com/PhyberApex/mamori/commit/e7774f32b7d85236e5a7669202561fb8d80b6b8f))
* add GitHub issue and PR templates ([#77](https://github.com/PhyberApex/mamori/issues/77)) ([3cf160f](https://github.com/PhyberApex/mamori/commit/3cf160f95068fc5fcd6c0e9bddfd2f50e6ebf1c5)), closes [#72](https://github.com/PhyberApex/mamori/issues/72)
* **cli:** add repeatable -H flag for custom request headers ([#76](https://github.com/PhyberApex/mamori/issues/76)) ([6dcff0b](https://github.com/PhyberApex/mamori/commit/6dcff0bdd32f55770a37d358621ab6239f988496)), closes [#60](https://github.com/PhyberApex/mamori/issues/60)
* **scanner:** add CORS misconfiguration checker ([#69](https://github.com/PhyberApex/mamori/issues/69)) ([9070502](https://github.com/PhyberApex/mamori/commit/9070502894a4a7881e314c8b7d5d4e289152b0c4))
* **scanner:** add Cross-Origin-Embedder-Policy checker ([#81](https://github.com/PhyberApex/mamori/issues/81)) ([bb54faa](https://github.com/PhyberApex/mamori/commit/bb54faad8040832973d3254d05f26a1b06037e1d))
* **scanner:** add Cross-Origin-Opener-Policy checker ([#80](https://github.com/PhyberApex/mamori/issues/80)) ([04ec0a9](https://github.com/PhyberApex/mamori/commit/04ec0a97e62dfddae88f26a6f8dc6189dbe631c8))
* **scanner:** add Cross-Origin-Resource-Policy checker ([#63](https://github.com/PhyberApex/mamori/issues/63)) ([85ae880](https://github.com/PhyberApex/mamori/commit/85ae8809be33ad4e1b9da45b7b51e0925a752c0c))
* **scanner:** add mixed-content checker for https targets ([#75](https://github.com/PhyberApex/mamori/issues/75)) ([fee96be](https://github.com/PhyberApex/mamori/commit/fee96be2ce269b173dbec464435846acdd57e667))
* **scanner:** add Permissions-Policy checker ([#61](https://github.com/PhyberApex/mamori/issues/61)) ([945e61d](https://github.com/PhyberApex/mamori/commit/945e61d48550cac2566bb2df95a683035e3e5f44))
* **scanner:** add SARIF output format ([#71](https://github.com/PhyberApex/mamori/issues/71)) ([bac7dd2](https://github.com/PhyberApex/mamori/commit/bac7dd2943495bdd9b61d9a55ed52bf0541f0b6b))
* **scanner:** add server banner disclosure checker ([#65](https://github.com/PhyberApex/mamori/issues/65)) ([8521f4a](https://github.com/PhyberApex/mamori/commit/8521f4ad692b2d53fd4776b359822c644a64e9d5))
* **scanner:** add Subresource Integrity (SRI) checker ([#68](https://github.com/PhyberApex/mamori/issues/68)) ([545df08](https://github.com/PhyberApex/mamori/commit/545df08f6465f64cc68b8bf69f5d05e28b701dae))
* **scanner:** add X-XSS-Protection checker ([#82](https://github.com/PhyberApex/mamori/issues/82)) ([89e0361](https://github.com/PhyberApex/mamori/commit/89e0361b2921350c22bdcee6de091e4f1672af51)), closes [#41](https://github.com/PhyberApex/mamori/issues/41)
* **scanner:** flag weak CSP values beyond mere presence ([#64](https://github.com/PhyberApex/mamori/issues/64)) ([ce9a10c](https://github.com/PhyberApex/mamori/commit/ce9a10c4787cd3f80ae8efb2df916206bd79912c)), closes [#42](https://github.com/PhyberApex/mamori/issues/42)

## 1.0.0 (2026-08-23)


### Features

* add -o json NDJSON output and colored terminal report ([57df7e0](https://github.com/PhyberApex/mamori/commit/57df7e0ff10b42a4f1f92e5e5a1f6814aecf4b22)), closes [#20](https://github.com/PhyberApex/mamori/issues/20)
* **cli:** add -fail-on flag so CI can gate on scan severity ([#33](https://github.com/PhyberApex/mamori/issues/33)) ([0df010e](https://github.com/PhyberApex/mamori/commit/0df010e94f553df1beeac16f28f38a7200db8449))
* **config:** add optional YAML config file support ([#35](https://github.com/PhyberApex/mamori/issues/35)) ([0574567](https://github.com/PhyberApex/mamori/commit/05745673826d153900d033232042c4d871330818))
* resolve scan targets from args and piped stdin (ResolveTargets) ([8e427dd](https://github.com/PhyberApex/mamori/commit/8e427dd086434eb4b29b7262196229e751f896e6))
* scan concurrently via worker pool with -workers/-timeout config ([f3a36e3](https://github.com/PhyberApex/mamori/commit/f3a36e3e27a96585dfc52bcfd5693abc493a1d25)), closes [#19](https://github.com/PhyberApex/mamori/issues/19)
* scan URLs for the five core security headers with a plain terminal report ([5e24d7b](https://github.com/PhyberApex/mamori/commit/5e24d7babaf23dafb0cc73e2f388bd95cd71bdfd)), closes [#17](https://github.com/PhyberApex/mamori/issues/17)
* **scanner:** add Set-Cookie checker for Secure, HttpOnly, SameSite ([#32](https://github.com/PhyberApex/mamori/issues/32)) ([5bb8974](https://github.com/PhyberApex/mamori/commit/5bb8974f5c8448f2ebf154d944c697014db42ae2))
* **scanner:** detect present-but-ineffective header values ([#26](https://github.com/PhyberApex/mamori/issues/26)) ([e4097c5](https://github.com/PhyberApex/mamori/commit/e4097c5e0a44c328be15855b47e4a1ba51446193))
* security header scanner MVP — targets, worker pool, output formats ([d9b48ab](https://github.com/PhyberApex/mamori/commit/d9b48ab7aa0d0408f13d43b270b6241a0d9b6e92))
* **site:** dark terminal theme and fix duplicate headings ([2abae4f](https://github.com/PhyberApex/mamori/commit/2abae4f2285baa9fc9e9a51c8b4e435481b9445e))


### Bug Fixes

* add version field to golangci-lint config for v2 compatibility ([facdf51](https://github.com/PhyberApex/mamori/commit/facdf51bc25733700935fe687ebedf91afc1c130))
* drop invalid issues section from golangci-lint v2 config ([6c7beca](https://github.com/PhyberApex/mamori/commit/6c7becaf3124dee2841fa6acd37e5a0b3763669a))
* grant write permissions to release-please workflow for goreleaser ([58471c8](https://github.com/PhyberApex/mamori/commit/58471c8ec1d605ff1de290e0c8d135863a8a0c5d))
* **scanner:** validate X-Content-Type-Options is nosniff, not just present ([#31](https://github.com/PhyberApex/mamori/issues/31)) ([cabfc37](https://github.com/PhyberApex/mamori/commit/cabfc374d22e9e62255b10784764c06f66dc38fb))
* simplify golangci-lint config for v2, add minimal main.go ([4e6c8b7](https://github.com/PhyberApex/mamori/commit/4e6c8b79c4fef82ca244446b5fde5e218aafcafe))
* update golangci-lint config to v2 schema ([c4e788e](https://github.com/PhyberApex/mamori/commit/c4e788e329ab4b9a52af8b89071325c0dacbdd21))
* upgrade golangci-lint-action to v7 for Node 24 compatibility ([e163355](https://github.com/PhyberApex/mamori/commit/e163355b150e6dd09c1db03f12dc84a7acf4f1b9))
