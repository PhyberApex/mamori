# Changelog

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
