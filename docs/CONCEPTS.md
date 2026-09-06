# CertLight — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## Two ways a certificate ruins your day
The first one everybody knows: the certificate expires. The site goes down, everyone panics, someone renews it, it is over within the hour. Painful but obvious.
The second is far more common and almost never noticed: a certificate that is still valid, but configured wrongly. The browser on your laptop shows a green padlock. The site opens normally. Nobody complains.
Until one day an application cannot connect, and nobody knows why.
## The most common case: the incomplete chain
An HTTPS certificate does not stand alone. There is a chain: your site certificate is signed by an intermediate, and the intermediate by a root the operating system already trusts.
The server is supposed to send its site certificate and the intermediate. If the intermediate is missing, the client has to guess — and some clients can, some cannot.
Modern browsers usually can, because they cached the intermediate from a previous visit. So you open the site and everything looks fine.
The ones that cannot guess: mobile apps, HTTP libraries in a backend, curl on another server, partner integrations, IoT devices. All of them fail to connect — and those are precisely the systems with nobody sitting in front of them to complain.
We tested it: against a host with an incomplete chain, openssl s_client returns verify error 20/21 and curl returns error (60), while a browser opens it without a murmur.
This is the class of error an uptime monitor never reports, because from its point of view your site is up.
## The second case: old protocols quietly still accepted
TLS 1.0 and 1.1 were formally deprecated in 2020 and should no longer be accepted by anything.
Most people assume this is done and dusted. But switching them off is a configuration change someone has to make, and often nobody ever did — or it was done on one server and forgotten on the second.
In our test against six hosts, five still accepted TLS 1.1 — including a site that exists specifically to test things like this.
Your server will not tell you. It will just dutifully accept those old connections, because that is how it was configured.
## The rest, briefly
- Hostname mismatch — a legitimate certificate, but issued for a different name. Happens after a domain migration, or when one certificate is reused somewhere it should not be
- Unexpected self-signed — usually a leftover from a temporary install that was never replaced
- Ciphers and key lengths that are now below the accepted standard
## Why the findings list does not wear you out
Security tools have a bad habit: hundreds of findings on day one, and nobody opens them again by day three.
CertLight avoids that with three simple things:
- Every finding carries its fix — not just "TLS 1.1 detected", but what to change
- Auto-resolve — once you fix the cause, the finding disappears on the next scan. No ticket to close by hand
- One digest, not a hundred alerts — if many things appear at once, they are merged into one, worst first
## What CertLight is not
Not an uptime monitor. It will not tell you your site is down — plenty of tools do that, and you probably already use one.
What CertLight does is the layer those tools skip: the state of your certificates and TLS configuration, while the site still looks perfectly fine.
Not a host discoverer either. CertLight checks what you register. Finding the servers you forgot you had is a different job.
## One thing we say up front about pricing
The free edition gives you 10 hosts with all the same TLS checks.
For most organisations, 10 hosts will never be the limit that binds — and we would rather say so than let you discover it after paying.
What usually moves people to Pro is not the host count but where the warnings go. A dashboard you have to open yourself stops getting opened by the second week. A warning that lands in Slack or email keeps getting read.
## Try it yourself, and do not trust it until it matches
```
curl -LO https://github.com/nizartuanku/certlight/releases/latest/download/certlight-free-0.1.1-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/certlight/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf certlight-free-0.1.1-linux-amd64.tar.gz
cd certlight-0.1.1
./certlight -listen 127.0.0.1:8422
```
Register these three public test hosts: expired.badssl.com, self-signed.badssl.com, wrong.host.badssl.com.
Then compare CertLight's findings with the output of openssl s_client -connect <host>:443 run by you.
If they do not match, do not use the product. That is the right way to judge a security tool — ours included.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/certlight

## Terms used above

- Certificate chain — your site's certificate is signed by an intermediate, and the intermediate is signed by a root that the operating system already trusts. A client has to follow that chain all the way to the root before it will trust you.
- TLS 1.0 and 1.1 — versions of the encryption protocol no longer considered secure, formally deprecated since 2020.
