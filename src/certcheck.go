package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// verifyPEM 校验私钥与证书匹配、证书覆盖配置域名、链可解析且未过期。
func (a *App) verifyPEM(c Config) error {
	f := a.fileSet(c)
	fullchain, err := os.ReadFile(f["fullchain"])
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(f["key"])
	if err != nil {
		return err
	}
	leaf, _, err := parseCertificates(fullchain)
	if err != nil {
		return err
	}
	priv, err := parsePrivateKey(keyData)
	if err != nil {
		return err
	}
	leafPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return err
	}
	keyPub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(leafPub, keyPub) {
		return fmt.Errorf("私钥与 fullchain 中的证书不匹配")
	}
	if err := leaf.VerifyHostname(c.Domain); err != nil {
		return fmt.Errorf("证书不包含域名 %s: %w", c.Domain, err)
	}
	if c.Wildcard {
		if err := leaf.VerifyHostname("wildcard-check." + c.Domain); err != nil {
			return fmt.Errorf("证书不包含泛域名 *.%s: %w", c.Domain, err)
		}
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("证书已过期（%s）", leaf.NotAfter.Format("2006-01-02 15:04:05"))
	}
	if now.Add(5 * time.Minute).Before(leaf.NotBefore) {
		return fmt.Errorf("证书尚未生效（%s）", leaf.NotBefore.Format("2006-01-02 15:04:05"))
	}
	return nil
}

func parseCertificates(data []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("证书解析失败: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("证书文件里没有 CERTIFICATE 块")
	}
	return certs[0], certs, nil
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("私钥解析失败: %w", err)
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("不支持的私钥类型 %T", key)
			}
			return signer, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("EC 私钥解析失败: %w", err)
			}
			return key, nil
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("RSA 私钥解析失败: %w", err)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("私钥文件里没有可识别的私钥块")
}
