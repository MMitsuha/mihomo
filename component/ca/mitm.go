package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/tls"
)

var currentMitmSerialNumber = time.Now().Unix()

type MitmAuthority struct {
	ca           *x509.Certificate
	caPrivateKey *rsa.PrivateKey
	privateKey   *rsa.PrivateKey
	keyID        []byte

	mutex        sync.RWMutex
	certs        map[string]*tls.Certificate
	validity     time.Duration
	organization string
}

func NewMitmAuthority(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*MitmAuthority, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pkixPub, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	if _, err = h.Write(pkixPub); err != nil {
		return nil, err
	}

	return &MitmAuthority{
		ca:           ca,
		caPrivateKey: caPrivateKey,
		privateKey:   privateKey,
		keyID:        h.Sum(nil),
		certs:        map[string]*tls.Certificate{},
		validity:     2 * 365 * 24 * time.Hour,
		organization: "Mihomo ManInTheMiddle Proxy Services",
	}, nil
}

func (a *MitmAuthority) GetCA() *x509.Certificate {
	return a.ca
}

func (a *MitmAuthority) NewTLSConfigForHost(hostname string) *tls.Config {
	return &tls.Config{
		Time: ntp.Now,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}
			return a.GetOrCreateCert(host)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func (a *MitmAuthority) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	hostname = normalizeCertHost(hostname)
	if hostname == "" {
		return nil, errors.New("empty certificate host")
	}

	a.mutex.RLock()
	tlsCertificate, ok := a.certs[hostname]
	a.mutex.RUnlock()
	if ok {
		return tlsCertificate, nil
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	if tlsCertificate, ok = a.certs[hostname]; ok {
		return tlsCertificate, nil
	}

	var dnsNames []string
	var ips []net.IP
	commonName := hostname
	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, hostname)
		parts := strings.Split(hostname, ".")
		if len(parts) > 2 {
			commonName = strings.Join(parts[len(parts)-2:], ".")
		}
	}

	serial := atomic.AddInt64(&currentMitmSerialNumber, 1)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{a.organization},
		},
		SubjectKeyId:          a.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(a.validity),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, a.ca, a.privateKey.Public(), a.caPrivateKey)
	if err != nil {
		return nil, err
	}

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsCertificate = &tls.Certificate{
		Certificate: [][]byte{raw, a.ca.Raw},
		PrivateKey:  a.privateKey,
		Leaf:        x509c,
	}
	a.certs[hostname] = tlsCertificate
	return tlsCertificate, nil
}

func normalizeCertHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimRight(host, ".")
	return strings.ToLower(host)
}

func LoadMitmAuthority(caPath string, caKeyPath string) (*MitmAuthority, error) {
	rootCACert, err := tls.LoadX509KeyPair(caPath, caKeyPath)
	if err != nil {
		return nil, err
	}

	privateKey, ok := rootCACert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("MITM CA private key must be RSA")
	}

	x509c, err := x509.ParseCertificate(rootCACert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return NewMitmAuthority(x509c, privateKey)
}

func GenerateAndSaveMitmCA(caPath string, caKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   "Mihomo Root CA",
			Organization: []string{"Mihomo Trust Services"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now().Add(-(time.Hour * 24 * 60)),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 25),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caRaw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privateKey.Public(), privateKey)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(caKeyPath), 0o700); err != nil {
		return err
	}

	caOut, err := os.OpenFile(caPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer caOut.Close()

	if err = pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caRaw}); err != nil {
		return err
	}

	caKeyOut, err := os.OpenFile(caKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer caKeyOut.Close()

	return pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}
