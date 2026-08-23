package certlight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nizartuanku/certlight/core"
	"github.com/nizartuanku/certlight/sched"
	"github.com/nizartuanku/certlight/store"
)

// --- certificate factory ----------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Hexward Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue creates a leaf for the given DNS names with a chosen expiry, signed by
// the CA (or self-signed when ca == nil).
func issue(t *testing.T, ca *testCA, dns []string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dns[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dns,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signKey := tpl, key // self-signed default
	if ca != nil {
		parent, signKey = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// serveTLS starts a TLS listener with the given cert and returns host:port.
func serveTLS(t *testing.T, pair tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Complete the handshake so the client gets ConnectionState.
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// collectOn runs Collect against addr, treating "localhost" as the hostname.
func collectOn(t *testing.T, cw *CertLight, addr string) []core.Finding {
	t.Helper()
	_, port, _ := net.SplitHostPort(addr)
	target, err := cw.ValidateTarget("localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	findings, err := cw.Collect(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func checksOf(fs []core.Finding) map[string]core.Finding {
	m := make(map[string]core.Finding)
	for _, f := range fs {
		m[f.Check] = f
	}
	return m
}

func newCW(ca *testCA) *CertLight {
	cw := New()
	cw.ProbeLegacyProtocols = false // Go's test server refuses legacy anyway; skip the extra dial
	if ca != nil {
		cw.Roots = ca.pool
	}
	return cw
}

// --- tests ------------------------------------------------------------------

// A healthy certificate (trusted, correct name, 1 year left) must produce
// ZERO findings. No noise is as important as catching real problems.
func TestCollect_HealthyCertIsAllClear(t *testing.T) {
	ca := newTestCA(t)
	addr := serveTLS(t, issue(t, ca, []string{"localhost"}, time.Now().Add(365*24*time.Hour)))
	findings := collectOn(t, newCW(ca), addr)
	if len(findings) != 0 {
		t.Fatalf("healthy cert must yield no findings, got: %+v", checksOf(findings))
	}
}

func TestCollect_ExpirySeverityLadder(t *testing.T) {
	cases := []struct {
		days int
		sev  core.Severity
	}{
		{20, core.SeverityMedium},
		{5, core.SeverityHigh},
		{1, core.SeverityCritical},
	}
	for _, tc := range cases {
		ca := newTestCA(t)
		addr := serveTLS(t, issue(t, ca, []string{"localhost"},
			time.Now().Add(time.Duration(tc.days)*24*time.Hour+time.Hour)))
		got := checksOf(collectOn(t, newCW(ca), addr))
		f, ok := got["tls.expiry"]
		if !ok {
			t.Fatalf("days=%d: expected tls.expiry finding, got %v", tc.days, got)
		}
		if f.Severity != tc.sev {
			t.Fatalf("days=%d: want severity %s, got %s", tc.days, tc.sev, f.Severity)
		}
		if f.Remediation == "" {
			t.Fatalf("days=%d: finding missing remediation", tc.days)
		}
	}
}

func TestCollect_ExpiredCertIsCritical(t *testing.T) {
	ca := newTestCA(t)
	// NotAfter in the past; NotBefore even earlier (set in issue()).
	addr := serveTLS(t, issue(t, ca, []string{"localhost"}, time.Now().Add(-48*time.Hour)))
	got := checksOf(collectOn(t, newCW(ca), addr))
	f, ok := got["tls.expired"]
	if !ok {
		t.Fatalf("expected tls.expired, got %v", got)
	}
	if f.Severity != core.SeverityCritical {
		t.Fatalf("expired must be critical, got %s", f.Severity)
	}
	// An expired cert also fails chain verification (CurrentTime past NotAfter)
	// — that is correct and expected; but tls.expiry (the countdown) must NOT
	// also fire alongside tls.expired.
	if _, dup := got["tls.expiry"]; dup {
		t.Fatal("tls.expiry must not fire together with tls.expired")
	}
}

func TestCollect_HostnameMismatch(t *testing.T) {
	ca := newTestCA(t)
	addr := serveTLS(t, issue(t, ca, []string{"othersite.example"}, time.Now().Add(365*24*time.Hour)))
	got := checksOf(collectOn(t, newCW(ca), addr))
	if _, ok := got["tls.hostname_mismatch"]; !ok {
		t.Fatalf("expected tls.hostname_mismatch, got %v", got)
	}
}

func TestCollect_SelfSignedIsUntrusted(t *testing.T) {
	// Self-signed, and CertLight trusts only the (unrelated) test CA.
	ca := newTestCA(t)
	addr := serveTLS(t, issue(t, nil, []string{"localhost"}, time.Now().Add(365*24*time.Hour)))
	got := checksOf(collectOn(t, newCW(ca), addr))
	f, ok := got["tls.untrusted_chain"]
	if !ok {
		t.Fatalf("expected tls.untrusted_chain, got %v", got)
	}
	if f.Evidence["self_signed"] != true {
		t.Fatalf("evidence should mark self_signed, got %v", f.Evidence)
	}
}

func TestValidateTarget(t *testing.T) {
	cw := New()
	ok := []struct{ in, canonical string }{
		{"example.com", "example.com:443"},
		{"example.com:8443", "example.com:8443"},
		{" example.com ", "example.com:443"},
	}
	for _, c := range ok {
		got, err := cw.ValidateTarget(c.in)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", c.in, err)
		}
		if got.Canonical != c.canonical {
			t.Fatalf("%q: want %q got %q", c.in, c.canonical, got.Canonical)
		}
	}
	for _, bad := range []string{"", "https://example.com", "example.com/path"} {
		if _, err := cw.ValidateTarget(bad); err == nil {
			t.Fatalf("%q: expected validation error", bad)
		}
	}
}

// The full stack, end to end: scheduler drives CertLight against a live local
// TLS server with an expiring cert; the finding must land in SQLite-compatible
// storage via the reconcile engine, and a second sweep must stay silent.
func TestEndToEnd_SchedulerCertLightStore(t *testing.T) {
	ca := newTestCA(t)
	addr := serveTLS(t, issue(t, ca, []string{"localhost"}, time.Now().Add(10*24*time.Hour)))
	_, port, _ := net.SplitHostPort(addr)

	cw := newCW(ca)
	ms := store.NewMemStore()
	engine := store.NewEngine(ms)
	s := sched.New(engine, sched.Config{ScanTimeout: 5 * time.Second})
	if err := s.Register(cw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddTarget("certwatch", "localhost:"+port); err != nil {
		t.Fatal(err)
	}

	// First sweep: the expiry finding opens.
	if err := s.ScanNow(context.Background(), "certwatch"); err != nil {
		t.Fatal(err)
	}
	open, _ := ms.ListOpen("certwatch")
	if len(open) != 1 || open[0].Check != "tls.expiry" {
		t.Fatalf("want exactly the tls.expiry finding open, got %+v", open)
	}

	// Second sweep: same problem, same fingerprint → still exactly one.
	if err := s.ScanNow(context.Background(), "certwatch"); err != nil {
		t.Fatal(err)
	}
	open, _ = ms.ListOpen("certwatch")
	if len(open) != 1 {
		t.Fatalf("second sweep must not duplicate findings, got %d", len(open))
	}
}
