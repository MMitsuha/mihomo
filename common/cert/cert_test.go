package cert

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAuthority(t *testing.T) {
	ca, key, err := NewAuthority("test CA", "test", time.Hour)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	if !ca.IsCA {
		t.Fatal("expected CA flag")
	}
	if key == nil {
		t.Fatal("expected private key")
	}
}

func TestGetOrCreateCert(t *testing.T) {
	ca, key, err := NewAuthority("test CA", "test", time.Hour)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	cfg, err := NewConfig(ca, key)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	// hostname certificate
	cert, err := cfg.GetOrCreateCert("api.example.com")
	if err != nil {
		t.Fatalf("GetOrCreateCert: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("expected parsed leaf")
	}
	if err := cert.Leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}

	// wildcard match should hit the cache via the +.example.com key
	cert2, err := cfg.GetOrCreateCert("billing.example.com")
	if err != nil {
		t.Fatalf("GetOrCreateCert(2): %v", err)
	}
	if cert2.Leaf == nil {
		t.Fatal("expected parsed leaf for second host")
	}
	if err := cert2.Leaf.VerifyHostname("billing.example.com"); err != nil {
		t.Fatalf("VerifyHostname billing: %v", err)
	}

	// IP literal certificate
	ipCert, err := cfg.GetOrCreateCert("192.0.2.1", net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("GetOrCreateCert ip: %v", err)
	}
	if len(ipCert.Leaf.IPAddresses) == 0 {
		t.Fatal("expected IP SAN")
	}
}

func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := GenerateAndSave(certPath, keyPath); err != nil {
		t.Fatalf("GenerateAndSave: %v", err)
	}
	for _, p := range []string{certPath, keyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", p)
		}
	}

	ca, key, err := LoadFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadFromFiles: %v", err)
	}
	if !ca.IsCA {
		t.Fatal("loaded cert should be CA")
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := ca.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("CA self-verify: %v", err)
	}

	if key == nil {
		t.Fatal("expected loaded key")
	}
}
