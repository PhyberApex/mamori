# Changelog

## [1.2.0](https://github.com/PhyberApex/mamori/compare/v1.1.0...v1.2.0) (2026-08-29)


### Features

* **config:** add pre-scan/post-scan shell command hooks ([#88](https://github.com/PhyberApex/mamori/issues/88)) ([8017dcd](https://github.com/PhyberApex/mamori/commit/8017dcd56c1c3c16f57ecfcde5094ca800612f17))
* **scanner:** add opt-in sensitive-path exposure checker ([#87](https://github.com/PhyberApex/mamori/issues/87)) ([1897919](https://github.com/PhyberApex/mamori/commit/18979198e973e4497a449d3612331fd560218735))
* **scanner:** add suppressions config to mark accepted-risk Findings ([#84](https://github.com/PhyberApex/mamori/issues/84)) ([f27e67c](https://github.com/PhyberApex/mamori/commit/f27e67cd89d2ad56fd44f7fc36d595103ce00632)), closes [#59](https://github.com/PhyberApex/mamori/issues/59)

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
