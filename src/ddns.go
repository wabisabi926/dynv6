package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func detectIP(rawURL string, wantV4 bool, timeout time.Duration) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("未配置探测地址")
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "dynv6/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("探测返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(body))
	ip := net.ParseIP(text)
	if ip == nil {
		return "", fmt.Errorf("探测结果不是合法 IP: %s", text)
	}
	if wantV4 && ip.To4() == nil {
		return "", fmt.Errorf("探测结果不是 IPv4: %s", text)
	}
	if !wantV4 && ip.To4() != nil {
		return "", fmt.Errorf("探测结果不是 IPv6: %s", text)
	}
	if !isPublicIP(ip) {
		return "", fmt.Errorf("探测结果不是公网 IP: %s", text)
	}
	return ip.String(), nil
}

// detectIPFromList 按逗号/分号/空格分隔依次尝试多个探测地址，返回第一个成功结果
func detectIPFromList(raw string, wantV4 bool, timeout time.Duration, logf func(string, ...any)) (string, error) {
	var lastErr error
	for _, u := range splitProbeList(raw) {
		ip, err := detectIP(u, wantV4, timeout)
		if err == nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("%s: %w", u, err)
		if logf != nil {
			logf("IP 探测失败 %s: %v", u, err)
		}
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("未配置探测地址")
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("所有探测地址都失败了")
}

func (a *App) handleProbe(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	c := a.getConfig()
	var v4, v6 []probeResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); v4 = probeAll(c.IPv4ProbeURL, true, 4*time.Second) }()
	go func() { defer wg.Done(); v6 = probeAll(c.IPv6ProbeURL, false, 4*time.Second) }()
	wg.Wait()
	writeJSON(w, map[string]any{
		"ok":           true,
		"network_hint": vpnInterfaceHint(),
		"ipv4":         v4,
		"ipv6":         v6,
	})
}

func joinWarning(w string) string {
	if w == "" {
		return ""
	}
	return "；" + w
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func splitProbeList(raw string) []string {
	var out []string
	for _, u := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '，' || r == '、' || r == ';' || r == '\n' || r == ' ' || r == '\t'
	}) {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

type probeResult struct {
	URL string `json:"url"`
	IP  string `json:"ip"`
	Err string `json:"error"`
	MS  int64  `json:"ms"`
}

// probeFirstTwo 依次探测，最多收集两个成功结果，用于发现多出口/代理导致的 IP 不一致
func probeFirstTwo(raw string, wantV4 bool, timeout time.Duration, logf func(string, ...any)) (string, []probeResult, error) {
	var results []probeResult
	var lastErr error
	for _, u := range splitProbeList(raw) {
		start := time.Now()
		ip, err := detectIP(u, wantV4, timeout)
		r := probeResult{URL: u, IP: ip, MS: time.Since(start).Milliseconds()}
		if err != nil {
			r.Err = err.Error()
			lastErr = fmt.Errorf("%s: %w", u, err)
			if logf != nil {
				logf("IP 探测失败 %s: %v", u, err)
			}
			continue
		}
		results = append(results, r)
		if len(results) >= 2 {
			break
		}
	}
	if len(results) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("未配置探测地址")
		}
		return "", results, lastErr
	}
	return results[0].IP, results, nil
}

// probeAll 返回每个探测源的结果，供“测试 IP 探测”使用；各源并发探测，整体约等于单次超时
func probeAll(raw string, wantV4 bool, timeout time.Duration) []probeResult {
	urls := splitProbeList(raw)
	out := make([]probeResult, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			start := time.Now()
			ip, err := detectIP(u, wantV4, timeout)
			r := probeResult{URL: u, IP: ip, MS: time.Since(start).Milliseconds()}
			if err != nil {
				r.Err = err.Error()
			}
			out[i] = r
		}(i, u)
	}
	wg.Wait()
	return out
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// ddnsNeedsUpdate 决定是否需要调用 dynv6：IP、域名或 Token 任一变化都算变化。
func ddnsNeedsUpdate(st State, c Config, ipv4, ipv6, tokenFP string, force bool) (bool, string) {
	if force {
		return true, "手动强制更新"
	}
	if st.LastDDNSDomain != c.Domain {
		return true, "域名已变更"
	}
	if st.LastDDNSTokenHash != tokenFP {
		return true, "Token 已变更"
	}
	if ipv4 != "" && ipv4 != st.LastIPv4 {
		return true, "IPv4 已变化"
	}
	if ipv6 != "" && ipv6 != st.LastIPv6 {
		return true, "IPv6 已变化"
	}
	return false, ""
}

func (a *App) runDDNS(force bool) error {
	c := a.getConfig()
	if c.Domain == "" || c.Token == "" {
		return fmt.Errorf("请先在设置中填写域名与 dynv6 HTTP Token")
	}
	// 无论成功失败都记录尝试时间，避免失败后每 30 秒重试并饿死证书检查
	a.setState(func(s *State) { s.LastDDNSAttempt = nowISO() })
	st := a.getState()
	if !c.EnableIPv4 && !c.EnableIPv6 && c.IPv4Override == "" && c.IPv6Override == "" {
		return fmt.Errorf("未启用 IPv4 或 IPv6，请到「设置」勾选至少一项")
	}
	if c.IPv4Override != "" {
		ip := net.ParseIP(c.IPv4Override)
		if ip == nil || ip.To4() == nil || !isPublicIP(ip) {
			return fmt.Errorf("手动指定的 IPv4 不是公网地址：%q", c.IPv4Override)
		}
	}
	if c.IPv6Override != "" {
		ip := net.ParseIP(c.IPv6Override)
		if ip == nil || ip.To4() != nil || !isPublicIP(ip) {
			return fmt.Errorf("手动指定的 IPv6 不是公网地址：%q", c.IPv6Override)
		}
	}
	if !c.EnableIPv6 && c.IPv6Override == "" && st.LastIPv6 != "" {
		a.log("IPv6 已关闭，但上次记录的 AAAA 地址 %s 不会自动清除；如需删除请到 dynv6 后台处理", st.LastIPv6)
	}
	ipv4, ipv6 := "", ""
	var v4err, v6err error
	warning := ""
	if c.EnableIPv4 || c.IPv4Override != "" {
		if c.IPv4Override != "" {
			ipv4 = c.IPv4Override
			a.log("IPv4 使用手动指定地址 %s（跳过探测）", ipv4)
		} else {
			v, results, err := probeFirstTwo(c.IPv4ProbeURL, true, 6*time.Second, a.log)
			if err != nil {
				v4err = err
				a.log("IPv4 探测失败: %v", err)
			} else {
				ipv4 = v
				if len(results) >= 2 && results[0].IP != results[1].IP {
					warning = fmt.Sprintf("警告：不同探测源返回不同 IP（%s=%s，%s=%s），可能启用了 VPN/代理/多出口，已采用第一个",
						hostOf(results[0].URL), results[0].IP, hostOf(results[1].URL), results[1].IP)
					a.log("%s", warning)
				}
			}
		}
	}
	if c.EnableIPv6 || c.IPv6Override != "" {
		if c.IPv6Override != "" {
			ipv6 = c.IPv6Override
			a.log("IPv6 使用手动指定地址 %s（跳过探测）", ipv6)
		} else {
			v, err := detectIPFromList(c.IPv6ProbeURL, false, 6*time.Second, nil)
			if err != nil {
				v6err = err
				a.log("IPv6 不可用，已跳过（不影响 IPv4）：%v", err)
				if st.LastIPv6 != "" {
					a.log("本次 IPv6 探测失败，dynv6 上旧的 AAAA 记录（%s）会保留；如需清除请手动处理", st.LastIPv6)
				}
			} else {
				ipv6 = v
			}
		}
	}
	if ipv4 == "" && ipv6 == "" {
		var parts []string
		if c.EnableIPv4 && c.IPv4Override == "" {
			parts = append(parts, fmt.Sprintf("IPv4: %v", v4err))
		}
		if c.EnableIPv6 && c.IPv6Override == "" {
			parts = append(parts, fmt.Sprintf("IPv6: %v", v6err))
		}
		return fmt.Errorf("IP 探测失败（%s）", strings.Join(parts, "；"))
	}
	a.log("探测结果 IPv4=%s IPv6=%s%s", ipv4, ipv6, joinWarning(warning))
	tokenFP := tokenFingerprint(c.Token)
	changed, reason := ddnsNeedsUpdate(st, c, ipv4, ipv6, tokenFP, force)
	if !changed {
		a.log("公网 IP/域名/Token 未变化（IPv4=%s IPv6=%s），跳过 DDNS 更新", ipv4, ipv6)
		a.setState(func(s *State) {
			s.LastDDNSAt = nowISO()
			s.LastDDNSResult = "IP 未变化，无需更新" + joinWarning(warning)
			s.LastDDNSDomain = c.Domain
			s.LastDDNSTokenHash = tokenFP
		})
		return nil
	}
	a.log("DDNS 需要更新：%s", reason)

	q := url.Values{}
	q.Set("zone", c.Domain)
	q.Set("token", c.Token)
	if ipv4 != "" {
		q.Set("ipv4", ipv4)
	}
	if ipv6 != "" {
		q.Set("ipv6", ipv6)
		if c.IPv6Prefix {
			q.Set("ipv6prefix", "auto")
		}
	}
	endpoint := "https://dynv6.com/api/update?" + q.Encode()
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return fmt.Errorf("调用 dynv6 更新接口失败: %s", maskSecrets(err.Error(), a.secrets(c)))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	text := strings.TrimSpace(string(body))
	lower := strings.ToLower(text)
	if resp.StatusCode != 200 || strings.Contains(lower, "invalid") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "badauth") || strings.Contains(lower, "error") {
		masked := maskSecrets(text, a.secrets(c))
		if resp.StatusCode == 401 || strings.Contains(lower, "invalid authentication token") || strings.Contains(lower, "token for authorization missing") {
			return fmt.Errorf("dynv6 拒绝了 Token（HTTP %d: %s）：请到 dynv6 后台 Keys → HTTP Tokens 重新复制本域名对应的 Token", resp.StatusCode, masked)
		}
		if resp.StatusCode == 404 {
			return fmt.Errorf("dynv6 找不到域名 %s（HTTP 404），请只填写域名本身，不要带 https:// 或路径", c.Domain)
		}
		return fmt.Errorf("dynv6 拒绝更新（HTTP %d）: %s", resp.StatusCode, masked)
	}
	if text == "" {
		text = "更新成功"
	}
	a.log("DDNS 更新成功 zone=%s ipv4=%s ipv6=%s 响应=%s%s", c.Domain, ipv4, ipv6, maskSecrets(text, a.secrets(c)), joinWarning(warning))
	a.setState(func(s *State) {
		s.LastDDNSAt = nowISO()
		s.LastDDNSResult = "更新成功" + joinWarning(warning)
		s.LastDDNSDomain = c.Domain
		s.LastDDNSTokenHash = tokenFP
		if ipv4 != "" {
			s.LastIPv4 = ipv4
		}
		if ipv6 != "" {
			s.LastIPv6 = ipv6
		}
	})
	a.notify("DDNS 更新成功", fmt.Sprintf("域名：%s\nIPv4：%s\nIPv6：%s%s", c.Domain, ipv4, ipv6, joinWarning(warning)))
	return nil
}
