package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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

func (a *App) prepareAcme(c Config) (string, error) {
	home := a.acmeHome(c)
	read := func(diskRel, embedRel string) ([]byte, error) {
		if data, err := os.ReadFile(filepath.Join(a.paths.Dest, "vendor", diskRel)); err == nil {
			return data, nil
		}
		return embeddedVendor.ReadFile("embedded/" + embedRel)
	}
	script, err := read("acme.sh", "acme.sh")
	if err != nil {
		return "", fmt.Errorf("缺少内置 acme.sh，请重新构建: %w", err)
	}
	plugin, err := read(filepath.Join("dnsapi", "dns_dynv6.sh"), "dnsapi/dns_dynv6.sh")
	if err != nil {
		return "", fmt.Errorf("缺少内置 dns_dynv6 插件，请重新构建: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "dnsapi"), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(home, "acme.sh"), script, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(home, "dnsapi", "dns_dynv6.sh"), plugin, 0755); err != nil {
		return "", err
	}
	return home, nil
}

func (a *App) acmeArgs(c Config, extra ...string) ([]string, []string, string, error) {
	if c.Domain == "" || c.Token == "" {
		return nil, nil, "", fmt.Errorf("请先在设置中填写域名与 dynv6 HTTP Token")
	}
	if !a.tools.HasShell() {
		return nil, nil, "", fmt.Errorf("当前系统找不到 sh，无法执行证书签发。Windows 请先安装 Git for Windows（自带 sh/openssl）；DDNS 与分发不受影响")
	}
	home, err := a.prepareAcme(c)
	if err != nil {
		return nil, nil, "", err
	}
	args := append([]string{a.acmePath(filepath.Join(home, "acme.sh"))}, extra...)
	args = append(args, "--home", a.acmePath(home))
	env := []string{
		"DYNV6_TOKEN=" + c.Token,
		"ACME_NO_COLOR=1",
	}
	return args, env, home, nil
}

// acmePath 在 Windows 上把路径转成 C:/... 形式，Git Bash 下的 acme.sh 才能正确处理
func (a *App) acmePath(p string) string {
	if runtime.GOOS == "windows" {
		return filepath.ToSlash(p)
	}
	return p
}

func isECC(c Config) bool {
	return strings.HasPrefix(c.KeyLength, "ec-")
}

// acme.sh 的 CA 地址常量（与内置 acme.sh 的 CA_LETSENCRYPT_V2 / _TEST 一致）
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

// certConfPath 定位 acme.sh 保存的域名配置（Le_API / Le_Domain 等）；优先当前密钥类型。
func (a *App) certConfPath(c Config) string {
	if c.Domain == "" {
		return ""
	}
	home := a.acmeHome(c)
	dirs := []string{c.Domain, c.Domain + "_ecc"}
	if isECC(c) {
		dirs = []string{c.Domain + "_ecc", c.Domain}
	}
	for _, dir := range dirs {
		p := filepath.Join(home, dir, c.Domain+".conf")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// confMismatch 检测 acme.sh 已保存的密钥长度/泛域名设置是否与当前配置一致。
func (a *App) confMismatch(c Config) (bool, string) {
	conf := a.certConfPath(c)
	if conf == "" {
		return false, ""
	}
	if saved := readConfValue(conf, "Le_Keylength"); saved != "" && saved != c.KeyLength {
		return true, fmt.Sprintf("密钥算法已从 %s 变为 %s", saved, c.KeyLength)
	}
	savedAlt := readConfValue(conf, "Le_Alt")
	hasWildcard := strings.Contains(savedAlt, "*."+c.Domain)
	if hasWildcard != c.Wildcard {
		if c.Wildcard {
			return true, "泛域名设置已开启"
		}
		return true, "泛域名设置已关闭"
	}
	return false, ""
}

// readConfValue 读取 acme.sh 域名配置文件中的 key='value' 形式的值
func readConfValue(path, key string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "'\"")
	}
	return ""
}

// acmeSkipError 表示 acme.sh 主动跳过（未到期/域名未变化/未签发），并非失败。
type acmeSkipError struct {
	out string
}

func (e *acmeSkipError) Error() string {
	return "acme.sh 跳过：" + summarizeCmdOutput(e.out)
}

func isAcmeSkip(err error) bool {
	var skip *acmeSkipError
	return errors.As(err, &skip)
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (a *App) runAcme(c Config, extra []string, timeout time.Duration) error {
	args, env, _, err := a.acmeArgs(c, extra...)
	if err != nil {
		return err
	}
	out, err := a.runCmd(a.tools.Sh, args, env, timeout, a.secrets(c), a.log)
	if err != nil {
		// acme.sh 用退出码 2 表示“无需续期/域名未变化/未签发”，不是错误
		if exitCode(err) == 2 {
			return &acmeSkipError{out: out}
		}
		msg := err.Error()
		if summary := summarizeCmdOutput(out); summary != "" {
			msg += "；" + summary
		}
		if reason := classifyAcmeError(out); reason != "" {
			msg += "；可能原因：" + reason
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// classifyAcmeError 从 acme.sh 输出中识别常见失败原因，给出可操作的建议
func classifyAcmeError(out string) string {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "no zone found") || strings.Contains(s, "matching zone") || strings.Contains(s, "not authorized to access the zone"):
		return "HTTP Token 无权访问该域名（zone）：请确认 Token 是账户级令牌，或属于当前域名"
	case strings.Contains(s, "invalid authentication token") || strings.Contains(s, "token for authorization missing") || strings.Contains(s, "unauthorized"):
		return "HTTP Token 无效或已过期，请到 dynv6 后台 Keys → HTTP Tokens 重新复制"
	case strings.Contains(s, "error adding txt"):
		return "创建 TXT 记录失败：多半是 Token 无权访问该域名，或域名不在当前 dynv6 账号下"
	case strings.Contains(s, "register account error") || strings.Contains(s, "too many") || strings.Contains(s, "429") || strings.Contains(s, "rate limit"):
		return "触发了证书机构限流或账户注册失败，请稍后再试（测试环境请用 letsencrypt_test）"
	case strings.Contains(s, "dns problem") || strings.Contains(s, "verify error") || strings.Contains(s, "challenge"):
		return "DNS 记录未生效或验证失败，可加大「DNS 生效等待」后重试"
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out"):
		return "网络或 DNS 查询超时，请检查设备出网、DNS 与代理/出口节点设置"
	default:
		return ""
	}
}

func (a *App) issueCert(c Config, force bool) error {
	if c.CA != "letsencrypt" && c.CA != "letsencrypt_test" {
		return fmt.Errorf("不支持的证书机构 %q：仅支持 letsencrypt 与 letsencrypt_test", c.CA)
	}
	// acme.sh 判断“是否跳过”只看域名列表，不看 CA；切换机构时必须显式 --force，
	// 否则会把旧证书原样当成本次结果（staging 证书被部署出去会直接不被信任）
	if saved := readConfValue(a.certConfPath(c), "Le_API"); saved != "" && saved != caServerURL(c.CA) {
		a.log("证书机构已从 %s 切换为 %s，本次强制重新签发", saved, caServerURL(c.CA))
		force = true
	}
	if mismatch, reason := a.confMismatch(c); mismatch {
		a.log("%s，本次强制重新签发", reason)
		force = true
	}
	args := []string{"--issue", "--dns", "dns_dynv6", "-d", c.Domain}
	if c.Wildcard {
		args = append(args, "-d", "*."+c.Domain)
	}
	args = append(args, "--server", c.CA, "--keylength", c.KeyLength, "--dnssleep", fmt.Sprintf("%d", c.DNSSleep))
	if c.Email != "" {
		args = append(args, "--accountemail", c.Email)
	}
	if force {
		args = append(args, "--force")
	}
	a.setStage("申请证书（DNS-01，等待 DNS 生效）")
	a.log("开始签发证书 domain=%s wildcard=%v ca=%s", c.Domain, c.Wildcard, c.CA)
	if err := a.runAcme(c, args, 10*time.Minute); err != nil {
		if isAcmeSkip(err) {
			a.log("acme.sh 判定无需重新签发（域名未变化/未到期），继续导出已有证书")
		} else {
			a.notify("证书签发失败", fmt.Sprintf("%s：%v", c.Domain, err))
			return err
		}
	}
	a.setStage("导出 PEM")
	if err := a.installPEM(c); err != nil {
		if isAcmeSkip(err) {
			return fmt.Errorf("acme.sh 跳过了签发，但未能导出已有证书；请点「立即签发」强制重新签发: %w", err)
		}
		a.notify("证书导出失败", fmt.Sprintf("%s：%v", c.Domain, err))
		return err
	}
	return nil
}

func (a *App) installPEM(c Config) error {
	f := a.fileSet(c)
	if err := os.MkdirAll(a.outDir(c), 0700); err != nil {
		return err
	}
	args := []string{"--install-cert", "-d", c.Domain,
		"--key-file", a.acmePath(f["key"]),
		"--fullchain-file", a.acmePath(f["fullchain"]),
		"--cert-file", a.acmePath(f["cert"]),
		"--ca-file", a.acmePath(f["chain"]),
	}
	if isECC(c) {
		args = append(args, "--ecc")
	}
	if err := a.runAcme(c, args, 5*time.Minute); err != nil {
		return err
	}
	mode := parseMode(c.FileMode)
	for _, k := range []string{"key", "cert", "fullchain", "chain"} {
		if _, err := os.Stat(f[k]); err != nil {
			return fmt.Errorf("证书导出不完整，缺少 %s", f[k])
		}
		_ = os.Chmod(f[k], mode)
	}
	if err := a.verifyPEM(c); err != nil {
		return fmt.Errorf("证书自检失败: %w", err)
	}
	a.log("PEM 证书已导出并自检通过：%s", a.outDir(c))
	return nil
}

func (a *App) renewCert(c Config, force bool) error {
	// 没有现成证书时 acme.sh 的 --renew 会直接报“域名不存在”，改为直接签发
	if _, err := os.Stat(a.fileSet(c)["fullchain"]); err != nil {
		a.log("未找到现有证书，改为首次签发")
		return a.issueCert(c, force)
	}
	// acme.sh 的 --renew 会沿用配置里记录的 CA/密钥长度/泛域名列表，任一项变化都要重新签发
	if saved := readConfValue(a.certConfPath(c), "Le_API"); saved != "" && saved != caServerURL(c.CA) {
		a.log("证书机构已切换为 %s，改为重新签发而不是续期", caServerURL(c.CA))
		return a.issueCert(c, true)
	}
	if mismatch, reason := a.confMismatch(c); mismatch {
		a.log("%s，改为重新签发而不是续期", reason)
		return a.issueCert(c, true)
	}
	args := []string{"--renew", "-d", c.Domain}
	if isECC(c) {
		args = append(args, "--ecc")
	}
	if force {
		args = append(args, "--force")
	}
	a.setStage("续期证书（DNS-01，等待 DNS 生效）")
	a.log("开始续期证书 domain=%s force=%v", c.Domain, force)
	if err := a.runAcme(c, args, 10*time.Minute); err != nil {
		if isAcmeSkip(err) {
			// acme home 丢了（找不到域名配置）时 acme.sh 也会用 2 表示跳过，此时必须重新签发
			if a.certConfPath(c) == "" {
				a.log("acme.sh 找不到已签发域名配置，改为重新签发")
				return a.issueCert(c, true)
			}
			a.log("acme.sh 判定暂不需要续期，继续导出已有证书")
		} else {
			a.notify("证书续期失败", fmt.Sprintf("%s：%v", c.Domain, err))
			return err
		}
	}
	// acme.sh 的 install-cert 参数会被记住并在 renew 时自动执行，这里再显式导出一次确保路径可控
	a.setStage("导出 PEM")
	if err := a.installPEM(c); err != nil {
		a.notify("证书导出失败", fmt.Sprintf("%s：%v", c.Domain, err))
		return err
	}
	return nil
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
