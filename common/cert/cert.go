package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/tls"
)

const (
	caValidity   = 25 * 365 * 24 * time.Hour
	leafValidity = 7 * 24 * time.Hour
	organization = "mihomo MITM"
	caCommonName = "mihomo Root CA"
)

var serialCounter atomic.Int64

func nextSerial() *big.Int {
	// Initialise once. CompareAndSwap so concurrent first callers don't
	// both Store and then both Add(1), which would mint duplicate serials.
	serialCounter.CompareAndSwap(0, time.Now().Unix())
	return big.NewInt(serialCounter.Add(1))
}

// Config issues leaf certificates signed by the embedded CA on demand.
type Config struct {
	ca           *x509.Certificate
	caPrivateKey *ecdsa.PrivateKey

	roots *x509.CertPool

	leafKey *ecdsa.PrivateKey
	keyID   []byte

	storage CertsStorage

	validity     time.Duration
	organization string
}

// NewAuthority generates a fresh self-signed CA certificate and private key.
func NewAuthority(commonName, org string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyID, err := publicKeyID(priv.Public())
	if err != nil {
		return nil, nil, err
	}

	now := ntp.Now()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}
	return caCert, priv, nil
}

// NewConfig wraps an existing CA into a Config that can mint leaf certificates.
func NewConfig(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*Config, error) {
	if ca == nil || caKey == nil {
		return nil, errors.New("cert: nil CA or private key")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyID, err := publicKeyID(leafKey.Public())
	if err != nil {
		return nil, err
	}

	return &Config{
		ca:           ca,
		caPrivateKey: caKey,
		roots:        roots,
		leafKey:      leafKey,
		keyID:        keyID,
		storage:      NewDomainTrieCertsStorage(),
		validity:     leafValidity,
		organization: organization,
	}, nil
}

// CA returns the embedded CA certificate.
func (c *Config) CA() *x509.Certificate { return c.ca }

// CACertPEM returns the CA certificate as PEM bytes.
func (c *Config) CACertPEM() []byte {
	if c.ca == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ca.Raw})
}

// SetValidity overrides the leaf certificate validity period.
func (c *Config) SetValidity(d time.Duration) {
	if d > 0 {
		c.validity = d
	}
}

// SetOrganization overrides the organization placed on issued leaf certificates.
func (c *Config) SetOrganization(org string) {
	if org != "" {
		c.organization = org
	}
}

// NewTLSConfigForHost returns a *tls.Config that mints a certificate for the
// requested SNI on demand.
func (c *Config) NewTLSConfigForHost(host string) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return c.GetOrCreateCert(name)
		},
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
		Time:               ntp.Now,
	}
}

// GetOrCreateCert returns a cached certificate for hostname or mints a new one.
// IPs may be provided to issue a SAN certificate covering literal addresses.
func (c *Config) GetOrCreateCert(hostname string, ips ...net.IP) (*tls.Certificate, error) {
	if cached, ok := c.storage.Get(hostname); ok {
		if cached.Leaf != nil {
			if _, err := cached.Leaf.Verify(x509.VerifyOptions{
				DNSName:     hostname,
				Roots:       c.roots,
				CurrentTime: ntp.Now(),
			}); err == nil {
				return cached, nil
			}
		}
	}

	var (
		key      = hostname
		topHost  = hostname
		dnsNames []string
	)

	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		parts := strings.Split(hostname, ".")
		if len(parts) > 2 {
			topIdx := len(parts) - 2
			topHost = strings.Join(parts[topIdx:], ".")
			dnsNames = append(dnsNames, topHost, "*."+topHost)
			for i := topIdx - 1; i > 0; i-- {
				dnsNames = append(dnsNames, "*."+strings.Join(parts[i:], "."))
			}
		} else {
			dnsNames = append(dnsNames, topHost, "*."+topHost)
		}
		key = "+." + topHost
	}

	now := ntp.Now()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject: pkix.Name{
			CommonName:   topHost,
			Organization: []string{c.organization},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(c.validity),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.leafKey.Public(), c.caPrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.leafKey,
		Leaf:        leaf,
	}
	c.storage.Set(key, cert)
	return cert, nil
}

// GenerateAndSave creates a fresh CA and writes the cert + key to disk.
func GenerateAndSave(certPath, keyPath string) error {
	ca, key, err := NewAuthority(caCommonName, organization, caValidity)
	if err != nil {
		return err
	}

	if err := writePEM(certPath, "CERTIFICATE", ca.Raw); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "PRIVATE KEY", keyBytes)
}

// LoadFromFiles loads a CA certificate + private key from disk.
func LoadFromFiles(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("cert: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("cert: invalid CA private key PEM")
	}
	priv, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func parsePrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if ec, ok := key.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, errors.New("cert: CA key must be ECDSA")
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("cert: unsupported private key format")
}

func publicKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(der)
	return sum[:], nil
}

func writePEM(path, blockType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
