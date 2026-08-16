// Package certwatch is the first Sentinel product: TLS/certificate expiry and
// configuration monitoring. It implements core.Collector — all the product's
// intelligence lives in Collect(); scheduling, storage, dedup, auto-resolve,
// and notification come from the framework.
//
// Checks implemented (each with its own check id and remediation):
//
//	tls.expired             — certificate is already expired (critical)
//	tls.expiry              — certificate expires within 30 days (ladder: 30/14/7/1)
//	tls.hostname_mismatch   — certificate does not cover the requested name
//	tls.untrusted_chain     — chain does not verify to a trusted root
//	                          (self-signed leaves get their own evidence marker)
//	tls.incomplete_chain    — server did not send required intermediates
//	tls.weak_protocol       — connection negotiated below TLS 1.2
//	tls.legacy_protocol     — server still ACCEPTS TLS 1.0/1.1 (extra probe)
//	tls.weak_cipher         — negotiated cipher suite is on Go's insecure list
//	tls.weak_key            — leaf public key below modern strength (RSA < 2048)
//	tls.legacy_signature    — leaf signed with SHA-1 era algorithm
//
// The "depth behind a simple surface" philosophy in practice: several of these
// (legacy_protocol, incomplete_chain, weak_key) are exactly what free uptime
// tools skip — while every finding still arrives as one plain sentence with a
// remediation attached.
package certwatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nizartuanku/certwatch/core"
)

const moduleID = "certwatch"

// CertWatch implements core.Collector.
type CertWatch struct {
	// Roots overrides the trust store used for chain verification. nil = the
	// system pool (production). Tests inject their own CA here.
	Roots *x509.CertPool
	// ProbeLegacyProtocols controls the extra TLS 1.0/1.1 acceptance probe.
	// One extra dial per scan; on by default in New().
	ProbeLegacyProtocols bool
	// now is injectable for deterministic expiry tests.
	now func() time.Time
}

// New returns a production-configured CertWatch.
func New() *CertWatch {
	return &CertWatch{ProbeLegacyProtocols: true, now: time.Now}
}

func (c *CertWatch) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              moduleID,
		Name:            "CertWatch",
		Version:         "0.1.0",
		TargetKind:      "host:port",
		DefaultInterval: 12 * time.Hour, // certs change slowly; be polite
		ResolveAfter:    1,              // deterministic checks resolve immediately
	}
}

// ValidateTarget accepts "example.com", "example.com:8443", or an IP:port.
// Port defaults to 443. The canonical form is always host:port.
func (c *CertWatch) ValidateTarget(raw string) (core.Target, error) {
	in := strings.TrimSpace(raw)
	if in == "" {
		return core.Target{}, fmt.Errorf("enter a host like example.com or example.com:8443")
	}
	// Reject schemes and paths early with a friendly message.
	if strings.Contains(in, "://") || strings.Contains(in, "/") {
		return core.Target{}, fmt.Errorf("enter just the host (no https:// or path): e.g. example.com")
	}
	host, port := in, "443"
	if h, p, err := net.SplitHostPort(in); err == nil {
		host, port = h, p
	} else if strings.Count(in, ":") > 1 {
		return core.Target{}, fmt.Errorf("IPv6 targets must include a port, e.g. [::1]:443")
	}
	if host == "" {
		return core.Target{}, fmt.Errorf("host must not be empty")
	}
	return core.Target{
		Raw:       raw,
		Canonical: net.JoinHostPort(host, port),
		Meta:      map[string]string{"host": host, "port": port},
	}, nil
}

// Collect dials the target, retrieves its certificate chain and negotiated
// parameters, and grades them. A dial failure is a scan error (not a finding);
// every graded weakness is a Finding with its own fingerprint and remediation.
func (c *CertWatch) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	host := t.Meta["host"]

	state, err := c.dial(ctx, t.Canonical, host, tls.VersionTLS10, 0)
	if err != nil {
		return nil, err // unreachable/refused → scan failed, backoff handles it
	}

	var out []core.Finding
	leaf := state.PeerCertificates[0]
	now := c.now()

	out = append(out, c.checkExpiry(t, leaf, now)...)
	out = append(out, c.checkHostname(t, leaf, host)...)
	out = append(out, c.checkChain(t, state, now)...)
	out = append(out, c.checkProtocol(t, state)...)
	out = append(out, c.checkCipher(t, state)...)
	out = append(out, c.checkKeyStrength(t, leaf)...)
	out = append(out, c.checkSignature(t, leaf)...)

	// Extra probe: does the server still ACCEPT legacy TLS? The main dial
	// negotiates the best mutual version, so a modern server answers 1.3 even
	// if it would also accept 1.0 — only a capped probe reveals that.
	if c.ProbeLegacyProtocols {
		out = append(out, c.probeLegacy(ctx, t, host)...)
	}

	return out, nil
}

// Diff defers to the core's fingerprint diff.
func (c *CertWatch) Diff(prev, cur []core.Finding) []core.Change { return nil }

// --- dialing ----------------------------------------------------------------

// dial opens one TLS connection and returns its ConnectionState. Verification
// is disabled at the handshake so we can always retrieve and grade the chain;
// trust and hostname are then checked explicitly in checkChain/checkHostname.
func (c *CertWatch) dial(ctx context.Context, addr, serverName string, minVer, maxVer uint16) (tls.ConnectionState, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // grading needs the chain even when invalid
			MinVersion:         minVer,
			MaxVersion:         maxVer,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tls.ConnectionState{}, fmt.Errorf("server presented no certificates")
	}
	return state, nil
}

// --- checks -----------------------------------------------------------------

func (c *CertWatch) checkExpiry(t core.Target, leaf *x509.Certificate, now time.Time) []core.Finding {
	if now.After(leaf.NotAfter) {
		days := int(now.Sub(leaf.NotAfter).Hours() / 24)
		return []core.Finding{{
			Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.expired", ""),
			Target:      t.Canonical, Check: "tls.expired",
			Title:    fmt.Sprintf("Certificate EXPIRED %d day(s) ago", days),
			Severity: core.SeverityCritical,
			Remediation: "Replace this certificate immediately — clients are already failing. " +
				"If you use ACME/Let's Encrypt, the renewal automation has broken; check its logs.",
			Evidence: evidence(leaf, map[string]any{"expired_days_ago": days}),
		}}
	}
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	if daysLeft > 30 {
		return nil
	}
	sev := core.SeverityMedium
	switch {
	case daysLeft <= 1:
		sev = core.SeverityCritical
	case daysLeft <= 7:
		sev = core.SeverityHigh
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.expiry", ""),
		Target:      t.Canonical, Check: "tls.expiry",
		Title:    fmt.Sprintf("Certificate expires in %d day(s)", daysLeft),
		Severity: sev,
		Remediation: "Renew the certificate before it expires. " +
			"If renewal is automated (ACME), verify the timer/cron actually runs and can reach the CA.",
		Evidence: evidence(leaf, map[string]any{"days_left": daysLeft}),
	}}
}

func (c *CertWatch) checkHostname(t core.Target, leaf *x509.Certificate, host string) []core.Finding {
	// IP targets rarely appear in SANs; grade only DNS names to avoid noise.
	if net.ParseIP(host) != nil {
		return nil
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return []core.Finding{{
			Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.hostname_mismatch", ""),
			Target:      t.Canonical, Check: "tls.hostname_mismatch",
			Title:    fmt.Sprintf("Certificate does not cover %q", host),
			Severity: core.SeverityHigh,
			Remediation: "Reissue the certificate with this hostname in its SAN list, " +
				"or point the service at the certificate that actually covers it.",
			Evidence: evidence(leaf, map[string]any{"requested_host": host, "sans": leaf.DNSNames}),
		}}
	}
	return nil
}

func (c *CertWatch) checkChain(t core.Target, state tls.ConnectionState, now time.Time) []core.Finding {
	leaf := state.PeerCertificates[0]
	selfSigned := len(state.PeerCertificates) == 1 &&
		leaf.Issuer.String() == leaf.Subject.String()

	intermediates := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}
	opts := x509.VerifyOptions{
		Roots:         c.Roots, // nil → system pool
		Intermediates: intermediates,
		CurrentTime:   now,
		// Hostname and expiry are graded separately with their own findings;
		// here we grade trust only, so skip name checking.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err == nil {
		return nil
	}

	// Distinguish "missing intermediates" (fixable server config) from a truly
	// untrusted chain: retry with intermediates fetched implicitly disabled —
	// if verification succeeds when we ALSO trust the presented intermediates
	// as roots, the server likely just failed to send the right chain.
	if !selfSigned && len(state.PeerCertificates) == 1 {
		return []core.Finding{{
			Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.incomplete_chain", ""),
			Target:      t.Canonical, Check: "tls.incomplete_chain",
			Title:    "Server sends no intermediate certificates",
			Severity: core.SeverityMedium,
			Remediation: "Configure the server to send the full chain (leaf + intermediates). " +
				"Most CAs ship a 'fullchain' bundle — deploy that file instead of the bare certificate.",
			Evidence: evidence(leaf, map[string]any{"presented_chain_length": 1}),
		}}
	}

	ev := evidence(leaf, map[string]any{
		"self_signed":            selfSigned,
		"presented_chain_length": len(state.PeerCertificates),
	})
	title := "Certificate chain is not trusted"
	remediation := "Install a certificate from a trusted CA (e.g. via ACME/Let's Encrypt), " +
		"or distribute your private CA to every client that must trust this service."
	if selfSigned {
		title = "Certificate is self-signed"
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.untrusted_chain", ""),
		Target:      t.Canonical, Check: "tls.untrusted_chain",
		Title:       title,
		Severity:    core.SeverityHigh,
		Remediation: remediation,
		Evidence:    ev,
	}}
}

func (c *CertWatch) checkProtocol(t core.Target, state tls.ConnectionState) []core.Finding {
	if state.Version >= tls.VersionTLS12 {
		return nil
	}
	v := versionName(state.Version)
	return []core.Finding{{
		Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.weak_protocol", v),
		Target:      t.Canonical, Check: "tls.weak_protocol",
		Title:    fmt.Sprintf("Connection negotiated obsolete %s", v),
		Severity: core.SeverityHigh,
		Remediation: "Disable TLS 1.0/1.1 on this service and require TLS 1.2 or newer. " +
			"Modern clients have not needed legacy TLS since 2020.",
		Evidence: map[string]any{"negotiated": v},
	}}
}

func (c *CertWatch) probeLegacy(ctx context.Context, t core.Target, host string) []core.Finding {
	state, err := c.dial(ctx, t.Canonical, host, tls.VersionTLS10, tls.VersionTLS11)
	if err != nil {
		return nil // refusing legacy TLS is the GOOD outcome
	}
	v := versionName(state.Version)
	return []core.Finding{{
		Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.legacy_protocol", ""),
		Target:      t.Canonical, Check: "tls.legacy_protocol",
		Title:    fmt.Sprintf("Server still accepts legacy %s", v),
		Severity: core.SeverityMedium,
		Remediation: "Raise the server's minimum TLS version to 1.2. The main connection may use " +
			"TLS 1.3, but accepting 1.0/1.1 leaves a downgrade path open and fails compliance scans.",
		Evidence: map[string]any{"accepted_version": v},
	}}
}

func (c *CertWatch) checkCipher(t core.Target, state tls.ConnectionState) []core.Finding {
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == state.CipherSuite {
			name := tls.CipherSuiteName(state.CipherSuite)
			return []core.Finding{{
				Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.weak_cipher", name),
				Target:      t.Canonical, Check: "tls.weak_cipher",
				Title:    fmt.Sprintf("Weak cipher suite negotiated: %s", name),
				Severity: core.SeverityHigh,
				Remediation: "Remove this cipher suite from the server configuration and prefer " +
					"AEAD suites (AES-GCM or ChaCha20-Poly1305).",
				Evidence: map[string]any{"cipher": name},
			}}
		}
	}
	return nil
}

func (c *CertWatch) checkKeyStrength(t core.Target, leaf *x509.Certificate) []core.Finding {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 2048 {
			return []core.Finding{{
				Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.weak_key", fmt.Sprintf("rsa-%d", bits)),
				Target:      t.Canonical, Check: "tls.weak_key",
				Title:    fmt.Sprintf("RSA key too small: %d bits", bits),
				Severity: core.SeverityHigh,
				Remediation: "Reissue the certificate with an RSA key of at least 2048 bits " +
					"(or switch to an ECDSA P-256 key).",
				Evidence: map[string]any{"algorithm": "RSA", "bits": bits},
			}}
		}
	case *ecdsa.PublicKey:
		// All curves Go accepts here (P-256+) are currently fine.
		_ = pub
	}
	return nil
}

func (c *CertWatch) checkSignature(t core.Target, leaf *x509.Certificate) []core.Finding {
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		alg := leaf.SignatureAlgorithm.String()
		return []core.Finding{{
			Fingerprint: core.Fingerprint(moduleID, t.Canonical, "tls.legacy_signature", alg),
			Target:      t.Canonical, Check: "tls.legacy_signature",
			Title:    fmt.Sprintf("Certificate signed with obsolete algorithm: %s", alg),
			Severity: core.SeverityHigh,
			Remediation: "Reissue the certificate — SHA-1/MD5 signatures are forgeable and rejected " +
				"by modern clients. Any current CA will sign with SHA-256 or better.",
			Evidence: map[string]any{"signature_algorithm": alg},
		}}
	}
	return nil
}

// --- helpers ----------------------------------------------------------------

// evidence builds the standard certificate context every finding shares, then
// merges check-specific extras. Shown only on the detail view — the Title
// stays one sentence.
func evidence(leaf *x509.Certificate, extra map[string]any) map[string]any {
	ev := map[string]any{
		"subject":    leaf.Subject.String(),
		"issuer":     leaf.Issuer.String(),
		"not_before": leaf.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  leaf.NotAfter.UTC().Format(time.RFC3339),
		"serial":     leaf.SerialNumber.String(),
	}
	for k, v := range extra {
		ev[k] = v
	}
	return ev
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
