package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func (a *App) acmeHome(c Config) string {
	return expand(c.AcmeHome, &c, &a.paths)
}

func (a *App) outDir(c Config) string {
	return expand(c.OutputDir, &c, &a.paths)
}

func (a *App) backupDir(c Config) string {
	return expand(c.BackupDir, &c, &a.paths)
}

func (a *App) prefix(c Config) string {
	p := expand(c.FilePrefix, &c, &a.paths)
	if p == "" || !validTemplateName(p) || strings.Contains(p, "${") {
		return c.Domain
	}
	return p
}

func (a *App) fileSet(c Config) map[string]string {
	d := a.outDir(c)
	p := a.prefix(c)
	return map[string]string{
		"key":       filepath.Join(d, p+".key"),
		"cert":      filepath.Join(d, p+".crt"),
		"fullchain": filepath.Join(d, p+".fullchain.crt"),
		"chain":     filepath.Join(d, p+".chain.crt"),
		"pfx":       filepath.Join(d, p+".pfx"),
		"p12":       filepath.Join(d, p+".p12"),
	}
}

func isECC(c Config) bool {
	return strings.HasPrefix(c.KeyLength, "ec-")
}

// Let's Encrypt 的 ACME 目录地址
const (
	caServerLE     = "https://acme-v02.api.letsencrypt.org/directory"
	caServerLETest = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func caServerURL(ca string) string {
	if ca == "letsencrypt_test" {
		return caServerLETest
	}
	return caServerLE
}

func keyTypeFor(keyLength string) certcrypto.KeyType {
	switch keyLength {
	case "ec-384":
		return certcrypto.EC384
	case "2048":
		return certcrypto.RSA2048
	case "4096":
		return certcrypto.RSA4096
	default:
		return certcrypto.EC256
	}
}

// acmeUser 实现 lego 的 registration.User 接口，账号密钥保存在 acme 目录，重启后复用。
type acmeUser struct {
	Email string
	key   crypto.Signer
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type acmeAccountFile struct {
	Email    string                 `json:"email,omitempty"`
	Resource *registration.Resource `json:"resource,omitempty"`
}

func (a *App) loadAcmeUser(home string) (*acmeUser, error) {
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, "account.key")
	var key *ecdsa.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		if signer, err := parsePrivateKey(data); err == nil {
			if k, ok := signer.(*ecdsa.PrivateKey); ok {
				key = k
			}
		}
	}
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 ACME 账户密钥失败: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		if err := atomicWrite(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
			return nil, fmt.Errorf("保存 ACME 账户密钥失败: %w", err)
		}
		key = k
	}
	user := &acmeUser{key: key}
	if data, err := os.ReadFile(filepath.Join(home, "account.json")); err == nil {
		var saved acmeAccountFile
		if json.Unmarshal(data, &saved) == nil {
			user.Email = saved.Email
			user.reg = saved.Resource
		}
	}
	return user, nil
}

func (a *App) saveAcmeAccount(home, email string, reg *registration.Resource) error {
	data, err := json.MarshalIndent(acmeAccountFile{Email: email, Resource: reg}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(home, "account.json"), data, 0600)
}

func (a *App) newAcmeClient(c Config, home string) (*lego.Client, error) {
	user, err := a.loadAcmeUser(home)
	if err != nil {
		return nil, err
	}
	user.Email = strings.TrimSpace(c.Email)
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caServerURL(c.CA)
	cfg.Certificate.KeyType = keyTypeFor(c.KeyLength)
	cfg.HTTPClient = &http.Client{Timeout: 90 * time.Second}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("初始化 ACME 客户端失败: %w", err)
	}
	if user.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("注册 ACME 账户失败: %s", describeAcmeError(err))
		}
		user.reg = reg
		if err := a.saveAcmeAccount(home, user.Email, reg); err != nil {
			a.log("保存 ACME 账户信息失败（不影响签发）: %v", err)
		}
	}
	provider := newDynv6DNS(c.Token, time.Duration(c.DNSSleep)*time.Second)
	provider.cancel = a.cancelChan()
	provider.store = newTXTStore(a.paths.Var)
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("设置 DNS-01 验证失败: %w", err)
	}
	return client, nil
}

// issueCert 通过 lego 走 DNS-01 直接签发，证书与私钥由 Go 写入，不再依赖 acme.sh。
func (a *App) issueCert(c Config, force bool) error {
	if c.Domain == "" || c.Token == "" {
		return fmt.Errorf("请先在设置中填写域名与 dynv6 HTTP Token")
	}
	if c.CA != "letsencrypt" && c.CA != "letsencrypt_test" {
		return fmt.Errorf("不支持的证书机构 %q：仅支持 letsencrypt 与 letsencrypt_test", c.CA)
	}
	home := a.acmeHome(c)
	a.setStage("申请证书（DNS-01，等待 DNS 生效）")
	a.log("开始签发证书（Go ACME）domain=%s wildcard=%v ca=%s key=%s", c.Domain, c.Wildcard, c.CA, c.KeyLength)
	client, err := a.newAcmeClient(c, home)
	if err != nil {
		a.notify("证书签发失败", fmt.Sprintf("%s：%v", c.Domain, err))
		return err
	}
	if a.wasCanceled() {
		return fmt.Errorf("任务已取消")
	}
	domains := []string{c.Domain}
	if c.Wildcard {
		domains = append(domains, "*."+c.Domain)
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
	if err != nil {
		msg := describeAcmeError(err)
		a.notify("证书签发失败", fmt.Sprintf("%s：%s", c.Domain, msg))
		return fmt.Errorf("%s", msg)
	}
	a.setStage("写入 PEM")
	if err := a.installPEM(c, res); err != nil {
		a.notify("证书导出失败", fmt.Sprintf("%s：%v", c.Domain, err))
		return err
	}
	return nil
}

// installPEM 把 lego 返回的证书写入 PEM 文件并自检。
func (a *App) installPEM(c Config, res *certificate.Resource) error {
	f := a.fileSet(c)
	if err := os.MkdirAll(a.outDir(c), 0700); err != nil {
		return err
	}
	fullchain := append(append([]byte{}, res.Certificate...), res.IssuerCertificate...)
	mode := parseMode(c.FileMode)
	files := map[string][]byte{
		"key":       res.PrivateKey,
		"cert":      res.Certificate,
		"fullchain": fullchain,
		"chain":     res.IssuerCertificate,
	}
	for _, k := range []string{"key", "cert", "fullchain", "chain"} {
		data := files[k]
		if len(data) == 0 {
			if k == "chain" {
				continue
			}
			return fmt.Errorf("证书导出不完整，缺少 %s", k)
		}
		// 私钥含敏感材料，无论 FileMode 如何配置都固定 0600
		writeMode := mode
		if k == "key" {
			writeMode = 0600
		}
		if err := atomicWrite(f[k], data, writeMode); err != nil {
			return err
		}
		_ = os.Chmod(f[k], writeMode)
	}
	if err := a.verifyPEM(c); err != nil {
		return fmt.Errorf("证书自检失败: %w", err)
	}
	a.log("PEM 证书已导出并自检通过：%s", a.outDir(c))
	return nil
}

// renewCert 在证书接近到期时重新签发；Go 客户端每次都会完整走一遍签发流程。
func (a *App) renewCert(c Config, force bool) error {
	if _, err := os.Stat(a.fileSet(c)["fullchain"]); err != nil {
		a.log("未找到现有证书，改为首次签发")
		return a.issueCert(c, force)
	}
	if !force {
		if t, err := certNotAfter(a.fileSet(c)["fullchain"]); err == nil {
			days := int(time.Until(t).Hours() / 24)
			if days > c.RenewDays {
				a.log("证书剩余 %d 天，未到续期阈值 %d 天，跳过续期", days, c.RenewDays)
				return nil
			}
		}
	}
	a.setStage("续期证书（DNS-01，等待 DNS 生效）")
	a.log("开始续期证书 domain=%s force=%v", c.Domain, force)
	return a.issueCert(c, true)
}

// certConfigMismatch 通过现有私钥/证书判断密钥算法与泛域名设置是否与当前配置一致。
func (a *App) certConfigMismatch(c Config) (bool, string) {
	f := a.fileSet(c)
	keyData, err := os.ReadFile(f["key"])
	if err != nil {
		return false, ""
	}
	signer, err := parsePrivateKey(keyData)
	if err != nil {
		return false, ""
	}
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		bits := k.Curve.Params().BitSize
		if !isECC(c) {
			return true, fmt.Sprintf("密钥算法已从 ec-%d 变为 %s", bits, c.KeyLength)
		}
		want := 256
		if c.KeyLength == "ec-384" {
			want = 384
		}
		if bits != want {
			return true, fmt.Sprintf("密钥算法已从 ec-%d 变为 %s", bits, c.KeyLength)
		}
	case *rsa.PrivateKey:
		if isECC(c) {
			return true, fmt.Sprintf("密钥算法已从 RSA-%d 变为 %s", k.N.BitLen(), c.KeyLength)
		}
		want := 2048
		if c.KeyLength == "4096" {
			want = 4096
		}
		if k.N.BitLen() != want {
			return true, fmt.Sprintf("密钥算法已从 RSA-%d 变为 %s", k.N.BitLen(), c.KeyLength)
		}
	}
	if data, err := os.ReadFile(f["fullchain"]); err == nil {
		if leaf, _, err := parseCertificates(data); err == nil {
			hasWildcard := false
			for _, name := range leaf.DNSNames {
				if strings.HasPrefix(name, "*.") {
					hasWildcard = true
					break
				}
			}
			if hasWildcard != c.Wildcard {
				if c.Wildcard {
					return true, "泛域名设置已开启"
				}
				return true, "泛域名设置已关闭"
			}
		}
	}
	return false, ""
}

// describeAcmeError 把 lego 的错误转换成可操作的中文提示。
func describeAcmeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if hint := classifyAcmeError(msg); hint != "" {
		return msg + "；可能原因：" + hint
	}
	return msg
}

// classifyAcmeError 从错误信息中识别常见失败原因，给出可操作的建议
func classifyAcmeError(out string) string {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "no zone found") || strings.Contains(s, "matching zone") || strings.Contains(s, "not authorized to access the zone"):
		return "HTTP Token 无权访问该域名（zone）：请确认 Token 是账户级令牌，或属于当前域名"
	case strings.Contains(s, "invalid authentication token") || strings.Contains(s, "token for authorization missing") || strings.Contains(s, "unauthorized") || strings.Contains(s, "401"):
		return "HTTP Token 无效或已过期，请到 dynv6 后台 Keys → HTTP Tokens 重新复制"
	case strings.Contains(s, "error adding txt"):
		return "创建 TXT 记录失败：多半是 Token 无权访问该域名，或域名不在当前 dynv6 账号下"
	case strings.Contains(s, "too many") || strings.Contains(s, "429") || strings.Contains(s, "rate limit"):
		return "触发了证书机构限流，请稍后再试（测试环境请用 letsencrypt_test）"
	case strings.Contains(s, "dns problem") || strings.Contains(s, "nxdomain") || strings.Contains(s, "propagation") || strings.Contains(s, "challenge"):
		return "DNS 记录未生效或验证失败，可加大「DNS 生效等待」后重试"
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out") || strings.Contains(s, "deadline exceeded"):
		return "网络或 DNS 查询超时，请检查设备出网、DNS 与代理/出口节点设置"
	default:
		return ""
	}
}

func certNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
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
			return time.Time{}, fmt.Errorf("证书解析失败: %w", err)
		}
		return cert.NotAfter, nil
	}
	return time.Time{}, fmt.Errorf("证书文件里没有 CERTIFICATE 块: %s", filepath.Base(path))
}
