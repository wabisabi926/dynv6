package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

func TestCAServerURL(t *testing.T) {
	if caServerURL("letsencrypt") != caServerLE {
		t.Fatal("letsencrypt 地址不对")
	}
	if caServerURL("letsencrypt_test") != caServerLETest {
		t.Fatal("letsencrypt_test 地址不对")
	}
	if caServerURL("") != caServerLE {
		t.Fatal("空值应回落到正式环境")
	}
}

func TestKeyTypeFor(t *testing.T) {
	cases := map[string]certcrypto.KeyType{
		"ec-256": certcrypto.EC256,
		"ec-384": certcrypto.EC384,
		"2048":   certcrypto.RSA2048,
		"4096":   certcrypto.RSA4096,
		"":       certcrypto.EC256,
	}
	for in, want := range cases {
		if got := keyTypeFor(in); got != want {
			t.Fatalf("keyTypeFor(%q) = %v，期望 %v", in, got, want)
		}
	}
}

func TestClassifyAcmeError(t *testing.T) {
	cases := []struct {
		out  string
		want string
	}{
		{"Could not find a matching zone for _acme-challenge.x.dynv6.net", "HTTP Token 无权访问该域名（zone）"},
		{"Error adding TXT record to domain", "创建 TXT 记录失败"},
		{"Register account error: 429", "限流"},
		{"Get https://acme...: Timeout was reached", "超时"},
		{"DNS problem: NXDOMAIN looking up TXT", "DNS 记录未生效"},
		{"invalid authentication token", "Token 无效"},
		{"some unknown failure", ""},
	}
	for _, c := range cases {
		got := classifyAcmeError(c.out)
		if (got == "") != (c.want == "") || (got != "" && !strings.Contains(got, c.want)) {
			t.Fatalf("classifyAcmeError(%q) = %q，应包含 %q", c.out, got, c.want)
		}
	}
}

func TestCertConfigMismatchKeyType(t *testing.T) {
	home := t.TempDir()
	out := t.TempDir()
	a := &App{paths: Paths{Var: t.TempDir()}}
	c := Config{Domain: "a.example.com", AcmeHome: home, OutputDir: out, KeyLength: "ec-256"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := a.fileSet(c)["key"]
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if mismatch, reason := a.certConfigMismatch(c); mismatch {
		t.Fatalf("密钥算法一致时不应报不匹配：%s", reason)
	}
	c.KeyLength = "2048"
	if mismatch, _ := a.certConfigMismatch(c); !mismatch {
		t.Fatal("密钥算法变化应检测到不匹配")
	}
}
