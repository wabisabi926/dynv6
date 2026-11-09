package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

type Target struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // pem | emby | plex
	Enabled  bool   `json:"enabled"`
	Dir      string `json:"dir"`
	Filename string `json:"filename"`
	Mode     string `json:"mode"` // 旧配置兼容，实际固定 0644
}

type Config struct {
	Domain string `json:"domain"`
	Token  string `json:"token"`
	Email  string `json:"email"`
	// Telegram 通知
	TGEnabled  bool   `json:"tg_enabled"`
	TGBotToken string `json:"tg_bot_token"`
	TGChatID   string `json:"tg_chat_id"`
	TGProxyURL string `json:"tg_proxy_url"`
	// 多出口 / VPN 环境可手动指定 IP，留空则自动探测
	IPv4Override string `json:"ipv4_override"`
	IPv6Override string `json:"ipv6_override"`
	// Schema 用于一次性配置迁移；旧配置没有该字段时为 0
	Schema int `json:"schema,omitempty"`
	// 旧版本拆分过两个令牌，实际是同一个 HTTP Token；保留字段仅用于自动迁移
	RestToken       string `json:"rest_token,omitempty"`
	DDNSToken       string `json:"ddns_token,omitempty"`
	Wildcard        bool   `json:"wildcard"`
	CA              string `json:"ca"`
	KeyLength       string `json:"key_length"`
	DNSSleep        int    `json:"dns_sleep"`
	RenewDays       int    `json:"renew_days"`
	DDNSIntervalMin int    `json:"ddns_interval_min"`
	CertCheckHours  int    `json:"cert_check_hours"`
	EnableIPv4      bool   `json:"enable_ipv4"`
	EnableIPv6      bool   `json:"enable_ipv6"`
	IPv4ProbeURL    string `json:"ipv4_probe_url"`
	IPv6ProbeURL    string `json:"ipv6_probe_url"`
	IPv6Prefix      bool   `json:"ipv6_prefix"`
	AcmeHome        string `json:"acme_home"`
	OutputDir       string `json:"output_dir"`
	BackupDir       string `json:"backup_dir"`
	FilePrefix      string `json:"file_prefix"`
	PFXPassword     string `json:"pfx_password"`
	P12Password     string `json:"p12_password"`
	FileMode        string `json:"file_mode"`
	AutoDDNS        bool   `json:"auto_ddns"`
	AutoRenew       bool   `json:"auto_renew"`
	AutoIssue       bool   `json:"auto_issue"`
	// AllowTestDeploy 允许把 Let's Encrypt 测试证书分发到目标；默认关闭，避免覆盖生产服务证书
	AllowTestDeploy bool     `json:"allow_test_deploy"`
	Targets         []Target `json:"targets"`
}

type Paths struct {
	Dest       string
	Etc        string
	Var        string
	Share      string
	Shares     []string
	Accessible []string
	Config     string
	State      string
	AuthFile   string
	Socket     string
	TokenFile  string
	DevPort    string
	// Listen 非空时以 TCP 服务模式监听该地址（Docker / 反向代理），不启用本地令牌，
	// 除健康检查与登录相关接口外都必须先登录管理员账号。
	Listen string
}

func (a *App) defaultConfig() Config {
	return Config{
		Schema:          2,
		CA:              "letsencrypt",
		KeyLength:       "ec-256",
		DNSSleep:        120,
		RenewDays:       30,
		DDNSIntervalMin: 5,
		CertCheckHours:  12,
		EnableIPv4:      true,
		EnableIPv6:      false,
		IPv4ProbeURL:    "https://ip.3322.net,https://api.ipify.org,https://ipv4.icanhazip.com,https://checkip.amazonaws.com",
		IPv6ProbeURL:    "https://api6.ipify.org,https://ipv6.icanhazip.com",
		IPv6Prefix:      false,
		AcmeHome:        "${APPDATA}/acme",
		OutputDir:       "${SHARE}",
		BackupDir:       "${APPDATA}/backup",
		FilePrefix:      "${DOMAIN}",
		FileMode:        "0600",
		AutoDDNS:        true,
		AutoRenew:       true,
		AutoIssue:       false,
		Targets: []Target{
			{ID: "emby", Name: "Emby", Kind: "emby", Enabled: false, Dir: "${OUTPUT}", Filename: "${DOMAIN}.pfx", Mode: "0644"},
			{ID: "plex", Name: "Plex", Kind: "plex", Enabled: false, Dir: "${OUTPUT}", Filename: "${DOMAIN}.p12", Mode: "0644"},
			{ID: "pem", Name: "自定义目录（PEM）", Kind: "pem", Enabled: false, Dir: "", Filename: "${DOMAIN}", Mode: "0644"},
		},
	}
}

func (a *App) loadConfig() error {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	def := a.defaultConfig()
	data, err := os.ReadFile(a.paths.Config)
	if err != nil {
		a.cfg = def
		return a.writeConfigLocked(def)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		// 配置损坏时用默认配置继续运行，但不覆盖原文件，便于用户手工修复
		a.cfg = def
		return fmt.Errorf("配置文件损坏，已使用默认配置运行（原文件未修改）: %w", err)
	}
	a.cfg = a.normalize(c)
	// 手工改坏的路径不能直接用于写私钥；回退到默认路径并记录日志
	if err := a.validateManagedPaths(a.cfg); err != nil {
		def := a.defaultConfig()
		a.log("配置路径无效，已回退到默认路径: %v", err)
		a.cfg.OutputDir = def.OutputDir
		a.cfg.AcmeHome = def.AcmeHome
		a.cfg.BackupDir = def.BackupDir
	}
	// 旧配置里拆成两个令牌，迁移后回写，避免磁盘上继续保留两份密钥
	if bytes.Contains(data, []byte("\"rest_token\"")) || bytes.Contains(data, []byte("\"ddns_token\"")) {
		_ = a.writeConfigLocked(a.cfg)
	}
	return nil
}

// normalize 补齐缺失字段，避免不完整配置把证书路径清空
func (a *App) normalize(c Config) Config {
	d := a.defaultConfig()
	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	c.Token = strings.TrimSpace(c.Token)
	c.Email = strings.TrimSpace(c.Email)
	c.IPv4ProbeURL = strings.TrimSpace(c.IPv4ProbeURL)
	c.IPv6ProbeURL = strings.TrimSpace(c.IPv6ProbeURL)
	c.TGBotToken = strings.TrimSpace(c.TGBotToken)
	c.TGChatID = strings.TrimSpace(c.TGChatID)
	c.TGProxyURL = strings.TrimSpace(c.TGProxyURL)
	c.IPv4Override = strings.TrimSpace(c.IPv4Override)
	c.IPv6Override = strings.TrimSpace(c.IPv6Override)
	c.CA = strings.TrimSpace(c.CA)
	c.KeyLength = strings.TrimSpace(c.KeyLength)
	c.AcmeHome = strings.TrimSpace(c.AcmeHome)
	c.OutputDir = strings.TrimSpace(c.OutputDir)
	c.BackupDir = strings.TrimSpace(c.BackupDir)
	c.FilePrefix = strings.TrimSpace(c.FilePrefix)
	c.FileMode = strings.TrimSpace(c.FileMode)
	// dynv6 的 DDNS 更新与 REST API Bearer 用的是同一个 HTTP Token
	if c.Token == "" {
		if c.RestToken != "" {
			c.Token = c.RestToken
		} else {
			c.Token = c.DDNSToken
		}
	}
	c.RestToken = ""
	c.DDNSToken = ""
	if c.CA == "" {
		c.CA = d.CA
	}
	if c.KeyLength == "" || !validKeyLength(c.KeyLength) {
		c.KeyLength = d.KeyLength
	}
	if c.DNSSleep < 0 {
		c.DNSSleep = d.DNSSleep
	}
	if c.RenewDays <= 0 {
		c.RenewDays = d.RenewDays
	}
	if c.DDNSIntervalMin <= 0 {
		c.DDNSIntervalMin = d.DDNSIntervalMin
	}
	if c.CertCheckHours <= 0 {
		c.CertCheckHours = d.CertCheckHours
	}
	if c.IPv4ProbeURL == "" || c.IPv4ProbeURL == "https://4.ipw.cn,https://api.ipify.org,https://ipv4.icanhazip.com,https://checkip.amazonaws.com" {
		c.IPv4ProbeURL = d.IPv4ProbeURL
	}
	if c.IPv6ProbeURL == "" || c.IPv6ProbeURL == "https://6.ipw.cn,https://api6.ipify.org,https://ipv6.icanhazip.com" {
		c.IPv6ProbeURL = d.IPv6ProbeURL
	}
	if c.AcmeHome == "" {
		c.AcmeHome = d.AcmeHome
	}
	if c.OutputDir == "" {
		c.OutputDir = d.OutputDir
	}
	if c.BackupDir == "" {
		c.BackupDir = d.BackupDir
	}
	if c.FilePrefix == "" {
		c.FilePrefix = d.FilePrefix
	}
	if c.FileMode == "" || !validFileMode(c.FileMode) {
		c.FileMode = d.FileMode
	}
	// nil 表示配置里没有 targets 字段（老版本），补默认目标；显式 [] 表示用户删空，保持为空
	if c.Targets == nil {
		c.Targets = d.Targets
	}
	// 分发目标固定 0644：Emby/Plex 以各自用户运行，0600 会读不到；PEM 私钥在 deploy 中单独收紧
	for i := range c.Targets {
		c.Targets[i].Mode = "0644"
		c.Targets[i].Dir = strings.TrimSpace(c.Targets[i].Dir)
		c.Targets[i].Filename = strings.TrimSpace(c.Targets[i].Filename)
		if c.Targets[i].Dir == "" {
			c.Targets[i].Enabled = false
		}
	}
	c.Schema = 2
	return c
}

func (a *App) writeConfigLocked(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(a.paths.Config, data, 0600)
}

// getConfig 应用运行时环境变量覆盖，让同一份配置可在飞牛 / Windows / Docker 下复用
func (a *App) getConfig() Config {
	a.cfgMu.RLock()
	c := a.cfg
	a.cfgMu.RUnlock()
	if v := os.Getenv("DYNV6_OUTPUT_DIR"); v != "" {
		c.OutputDir = v
	}
	if v := os.Getenv("DYNV6_BACKUP_DIR"); v != "" {
		c.BackupDir = v
	}
	if v := os.Getenv("DYNV6_ACME_HOME"); v != "" {
		c.AcmeHome = v
	}
	return c
}

// saveConfig 空字符串或 __KEEP__ 表示保留原有密钥
func (a *App) saveConfig(next Config) error {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	next = a.normalize(next)
	if next.CA != "letsencrypt" && next.CA != "letsencrypt_test" {
		return fmt.Errorf("证书机构只支持 letsencrypt 与 letsencrypt_test")
	}
	if !validKeyLength(next.KeyLength) {
		return fmt.Errorf("密钥算法只支持 ec-256、ec-384、2048、4096")
	}
	if !validFileMode(next.FileMode) {
		return fmt.Errorf("主输出权限只支持 0600 或 0640")
	}
	if next.Email != "" {
		if addr, err := mail.ParseAddress(next.Email); err != nil || addr.Address != next.Email {
			return fmt.Errorf("邮箱格式不合法")
		}
	}
	old := a.cfg
	keep := func(n, o string) string {
		if n == "__CLEAR__" {
			return ""
		}
		if n == "" || n == "__KEEP__" {
			return o
		}
		return n
	}
	next.Token = keep(next.Token, old.Token)
	next.RestToken = ""
	next.DDNSToken = ""
	next.PFXPassword = keep(next.PFXPassword, old.PFXPassword)
	next.P12Password = keep(next.P12Password, old.P12Password)
	next.TGBotToken = keep(next.TGBotToken, old.TGBotToken)
	if !isValidDomain(next.Domain) && next.Domain != "" {
		return fmt.Errorf("域名格式不合法")
	}
	// 手动指定 IP 必须是对应协议族的公网地址，避免把私网/回环地址写进 dynv6
	if v := next.IPv4Override; v != "" {
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("手动指定的 IPv4 不是合法 IPv4 地址：%q", v)
		}
		if !isPublicIP(ip) {
			return fmt.Errorf("手动指定的 IPv4 不是公网地址：%q", v)
		}
	}
	if v := next.IPv6Override; v != "" {
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("手动指定的 IPv6 不是合法 IPv6 地址：%q", v)
		}
		if !isPublicIP(ip) {
			return fmt.Errorf("手动指定的 IPv6 不是公网地址：%q", v)
		}
	}
	if !validTemplateName(next.FilePrefix) {
		return fmt.Errorf("文件名前缀不能包含路径分隔符或 ..")
	}
	for i := range next.Targets {
		t := &next.Targets[i]
		if !validTemplateName(t.Filename) {
			return fmt.Errorf("目标「%s」的文件名不能包含路径分隔符或 ..", t.Name)
		}
		if t.Dir == "" {
			continue
		}
		if hasDotDot(t.Dir) {
			return fmt.Errorf("目标「%s」的目录不能包含 ..", t.Name)
		}
		d := expand(t.Dir, &next, &a.paths)
		if !filepath.IsAbs(d) {
			return fmt.Errorf("目标「%s」的目录必须是绝对路径（展开后为 %q）", t.Name, d)
		}
		if runtimeEnv() == "fnOS" && !a.pathAllowedOnFnOS(filepath.Clean(d), next) {
			return fmt.Errorf("目标「%s」的目录不在已授权范围内（%q）；请先在飞牛「应用设置 → 授权路径」中授权", t.Name, d)
		}
	}
	if err := a.validateManagedPaths(next); err != nil {
		return err
	}
	if next.RenewDays < 1 || next.RenewDays > 80 {
		return fmt.Errorf("续期阈值需在 1-80 天之间")
	}
	if next.DDNSIntervalMin < 1 {
		next.DDNSIntervalMin = 5
	}
	if next.DDNSIntervalMin > 1440 {
		return fmt.Errorf("DDNS 检测间隔不能超过 1440 分钟")
	}
	if next.CertCheckHours < 1 {
		next.CertCheckHours = 12
	}
	if next.CertCheckHours > 168 {
		return fmt.Errorf("证书检查间隔不能超过 168 小时")
	}
	if next.DNSSleep < 0 {
		next.DNSSleep = 0
	}
	if next.DNSSleep > 600 {
		return fmt.Errorf("DNS 生效等待不能超过 600 秒")
	}
	if err := a.writeConfigLocked(next); err != nil {
		return err
	}
	a.cfg = next
	a.invalidatePathChecks()
	return nil
}

// publicConfig 返回脱敏后的配置，密钥字段用 __KEEP__ 占位
func publicConfig(c Config) Config {
	m := func(s string) string {
		if s != "" {
			return "__KEEP__"
		}
		return ""
	}
	c.Token = m(c.Token)
	c.RestToken = m(c.RestToken)
	c.DDNSToken = m(c.DDNSToken)
	c.PFXPassword = m(c.PFXPassword)
	c.P12Password = m(c.P12Password)
	c.TGBotToken = m(c.TGBotToken)
	return c
}

func (a *App) secrets(c Config) []string {
	return []string{c.Token, c.RestToken, c.DDNSToken, c.PFXPassword, c.P12Password, c.TGBotToken}
}

func validKeyLength(s string) bool {
	switch s {
	case "ec-256", "ec-384", "2048", "4096":
		return true
	}
	return false
}

func validFileMode(s string) bool {
	switch s {
	case "0600", "0640":
		return true
	}
	return false
}

// validateManagedPaths 校验输出/备份/acme 目录，避免相对路径、越界或写出授权范围。
func (a *App) validateManagedPaths(c Config) error {
	items := []struct {
		name string
		raw  string
	}{
		{"证书输出目录", c.OutputDir},
		{"备份目录", c.BackupDir},
		{"acme.sh 目录", c.AcmeHome},
	}
	for _, item := range items {
		raw := strings.TrimSpace(item.raw)
		if raw == "" {
			return fmt.Errorf("%s不能为空", item.name)
		}
		if hasDotDot(raw) {
			return fmt.Errorf("%s不能包含 ..", item.name)
		}
		expanded := expand(raw, &c, &a.paths)
		if strings.Contains(expanded, "${") {
			return fmt.Errorf("%s包含未知变量（展开后为 %q）", item.name, expanded)
		}
		if !filepath.IsAbs(expanded) {
			return fmt.Errorf("%s必须是绝对路径（展开后为 %q）", item.name, expanded)
		}
		clean := filepath.Clean(expanded)
		if clean == string(os.PathSeparator) || (len(clean) == 3 && clean[1] == ':') {
			return fmt.Errorf("%s不能是磁盘根目录", item.name)
		}
		if st, err := os.Stat(clean); err == nil && !st.IsDir() {
			return fmt.Errorf("%s不是目录：%s", item.name, clean)
		}
		if runtimeEnv() == "fnOS" && !a.pathAllowedOnFnOS(clean, c) {
			return fmt.Errorf("%s必须位于应用数据、共享目录或已授权路径内（当前 %q）；请先在飞牛「应用设置 → 授权路径」中授权", item.name, clean)
		}
		if real, err := filepath.EvalSymlinks(clean); err == nil && runtimeEnv() == "fnOS" && !a.pathAllowedOnFnOS(real, c) {
			return fmt.Errorf("%s通过符号链接指向了未授权目录（真实路径 %q）", item.name, real)
		}
	}
	return nil
}

// pathAllowedOnFnOS 判断目录是否在应用自身目录、共享目录或管理员授权路径内。
func (a *App) pathAllowedOnFnOS(p string, c Config) bool {
	roots := []string{a.paths.Var, a.paths.Etc, a.paths.Dest, a.paths.Share}
	roots = append(roots, a.paths.Shares...)
	roots = append(roots, a.paths.Accessible...)
	sep := string(os.PathSeparator)
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		root = filepath.Clean(expand(root, &c, &a.paths))
		if root == "" || strings.Contains(root, "${") {
			continue
		}
		if p == root || strings.HasPrefix(p, root+sep) {
			return true
		}
		if realRoot, err := filepath.EvalSymlinks(root); err == nil {
			if p == realRoot || strings.HasPrefix(p, realRoot+sep) {
				return true
			}
		}
	}
	return false
}
