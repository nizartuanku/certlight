# Sample run

This is real CertLight output, not a mockup. Five public test hosts were
registered on a lab instance of the free edition, scanned for real, and the
findings exported exactly as the API returned them — nothing in
[`sample-findings.json`](sample-findings.json) or
[`sample-summary.json`](sample-summary.json) was hand-edited.

**Source:** a lab instance of CertLight 0.1.3, free edition, with AI Assist
turned off so this sample shows the evidence engine on its own, not a model's
narration. The five targets are [badssl.com](https://badssl.com)'s public
test subdomains — a site built and maintained specifically so TLS tools have
real, reproducible certificates to check against. No customer host or
deployment is reproduced here.

## What was registered

| Target | What it's built to demonstrate |
|---|---|
| `expired.badssl.com` | a certificate that has already expired |
| `self-signed.badssl.com` | a self-signed leaf with no trusted chain |
| `incomplete-chain.badssl.com` | a server that omits its intermediate certificate |
| `wrong.host.badssl.com` | a valid, trusted certificate that does not cover the requested name |
| `tls-v1-1.badssl.com` | a server that still accepts the legacy TLS 1.1 protocol |

Free tier allows 10 hosts — this sample uses 5 of them, confirmed by
`GET /api/summary` in `sample-summary.json`.

## What CertLight found

| Target | Check | Severity |
|---|---|---|
| `expired.badssl.com:443` | `tls.expired` | **critical** |
| `expired.badssl.com:443` | `tls.untrusted_chain` | high |
| `self-signed.badssl.com:443` | `tls.untrusted_chain` | high |
| `wrong.host.badssl.com:443` | `tls.hostname_mismatch` | high |
| `incomplete-chain.badssl.com:443` | `tls.incomplete_chain` | medium |
| `expired.badssl.com:443` | `tls.legacy_protocol` | medium |
| `self-signed.badssl.com:443` | `tls.legacy_protocol` | medium |
| `incomplete-chain.badssl.com:443` | `tls.legacy_protocol` | medium |
| `tls-v1-1.badssl.com:443` | `tls.legacy_protocol` | medium |
| `wrong.host.badssl.com:443` | `tls.legacy_protocol` | medium |

10 open findings in total: 1 critical, 3 high, 6 medium — the exact counts in
`GET /api/summary`. The `legacy_protocol` check runs as an extra probe on
every target regardless of what the main connection negotiated, which is why
it fired on all five hosts: the badssl.com infrastructure behind every one of
these subdomains still accepts a TLS 1.1 handshake even though a normal
client would negotiate 1.2 or 1.3.

Two targets each surface two distinct problems with the *same* certificate —
`expired.badssl.com` is both expired **and** chains to an untrusted root,
and CertLight reports both rather than stopping at the first one it finds.

## Reading the evidence honestly

Every finding carries the certificate fields CertLight actually parsed —
issuer, subject, serial, validity window, and (for the hostname mismatch) the
SAN list it checked against the requested name. Nothing is summarized away;
see `evidence` in `sample-findings.json`.

This sample does not show `tls.weak_key`, `tls.weak_cipher`, `tls.legacy_signature`,
or staged expiry-countdown severities (30/14/7/1 days) — badssl.com's current
test hosts did not happen to exercise them at the time this sample was taken.
Those checks exist and are covered by the engine's own unit tests
(`certlight/collector_test.go`); this sample is a real run against real
servers, not a tour of every check.
