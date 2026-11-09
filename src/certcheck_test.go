package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func makeTestCert(t *testing.T, domain string, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain, "*." + domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeTestKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPEM(t *testing.T) {
	dir := t.TempDir()
	a := &App{paths: Paths{Var: dir}}
	c := Config{Domain: "example.com", OutputDir: dir, FilePrefix: "${DOMAIN}", Wildcard: true}
	f := a.fileSet(c)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, f["key"], key)
	cert := makeTestCert(t, c.Domain, key, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := os.WriteFile(f["fullchain"], cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPEM(c); err != nil {
		t.Fatalf("合法证书应通过自检: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, f["key"], otherKey)
	if err := a.verifyPEM(c); err == nil {
		t.Fatal("私钥不匹配应报错")
	}

	writeTestKey(t, f["key"], key)
	other := makeTestCert(t, "other.example.com", key, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := os.WriteFile(f["fullchain"], other, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPEM(c); err == nil {
		t.Fatal("域名不匹配应报错")
	}

	expired := makeTestCert(t, c.Domain, key, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err := os.WriteFile(f["fullchain"], expired, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPEM(c); err == nil {
		t.Fatal("过期证书应报错")
	}
}
