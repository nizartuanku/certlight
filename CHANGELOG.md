# Changelog

## Unreleased

- **The product page is reachable from inside the product.** When a free-edition limit is reached, the message that reports it now says where the paid editions are; the dashboard carries the same link in the Licence panel and the footer. It is a product URL, not a plan id, so it keeps working when plans change. No banner, no modal, no countdown.
- **Webhook verification identifiers renamed to Hexward.** The webhook now sends `X-Hexward-Token`, and keeps the previous header alongside it until **1 March 2027**, so a receiver written against the old name keeps working with no change at either end. A test asserts both headers carry the same secret.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, `cd`s into the extracted directory, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). When the unauthenticated GitHub API budget of 60 calls per hour is spent, the script names the rate limit and when it resets, instead of reporting "cannot reach".
- **`docs/CONCEPTS.md`** — what a certificate grade is claiming, what the configuration audit covers that an uptime check does not, and where the grade stops being useful.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here. The install block runs `docker build` before `docker run`, in the order that was actually tested.
- Packaging: the `LICENSE` / `license` collision is fixed and the real licence text ships with the source; one copyright holder is named.
- CI runs `gofmt`, `go vet` and `go test` on every push.

## 0.1.1 — 2026-08-23

CertWatch is now CertLight — same product, new name. The binary is `certlight` and the module path is `github.com/nizartuanku/certlight`; the old repository URLs redirect. Nothing else changed: same licence keys, same database format, same checks. The internal product id is unchanged, so existing licences and databases keep working and an in-place upgrade is just swapping the binary.

## 0.1.0 — 2026-08-16

First public release. Self-hosted TLS and certificate monitoring with the configuration audit most uptime tools skip: expiry at staged 30/14/7/1-day severities, expired certificates, hostname mismatch, untrusted and self-signed chains, missing intermediates, obsolete protocols, a legacy TLS 1.0/1.1 acceptance probe, weak ciphers, weak keys. Free edition: 10 hosts, 7-day history, webhook notifications. Dashboard on `http://127.0.0.1:8422`.
