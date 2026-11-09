package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func nowISO() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// hasDotDot 只拒绝真正的 .. 路径段；像 /vol1/a..b 这种合法目录名不应被误伤。
func hasDotDot(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// expand 替换路径/文件名模板中的变量
func expand(s string, c *Config, p *Paths) string {
	if s == "" {
		return ""
	}
	rep := map[string]string{
		"${DOMAIN}":  c.Domain,
		"${APPDATA}": p.Var,
		"${ETC}":     p.Etc,
		"${APPDEST}": p.Dest,
		"${SHARE}":   p.Share,
		"${OUTPUT}":  c.OutputDir,
		"${BACKUP}":  c.BackupDir,
		"${YEAR}":    time.Now().Format("2006"),
		"${MONTH}":   time.Now().Format("01"),
		"${EXT}":     "crt",
		"${KIND}":    "cert",
	}
	// 迭代展开，支持 ${OUTPUT} 引用另一个含变量的路径
	for i := 0; i < 4; i++ {
		prev := s
		for k, v := range rep {
			s = strings.ReplaceAll(s, k, v)
		}
		if s == prev {
			break
		}
	}
	return s
}

func parseMode(s string) os.FileMode {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0600
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0600
	}
	return os.FileMode(v)
}

func parseModeFor(s string, def os.FileMode) os.FileMode {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return def
	}
	return os.FileMode(v)
}

// atomicWrite 先写唯一临时文件再原子替换，避免并发写同一路径时互相覆盖。
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicWrite(dst, data, mode)
}

func maskSecrets(s string, secrets []string) string {
	for _, v := range secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

func isValidDomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func safeFileName(name string) bool {
	return name != "" && len(name) <= 255 && !hasControlChar(name) &&
		!strings.ContainsAny(name, "/\\") && name != "." && name != ".." && !strings.Contains(name, "..")
}

// validTemplateName 校验文件名/前缀模板不含路径分隔符、控制字符与上跳，避免写出目标目录
func validTemplateName(s string) bool {
	return !hasControlChar(s) && !strings.ContainsAny(s, "/\\") && !strings.Contains(s, "..")
}

// sameFilePath 判断源与目标是否同一个文件，避免分发目标与主输出目录相同时做无意义自复制
func sameFilePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if sa, err1 := os.Stat(a); err1 == nil {
		if sb, err2 := os.Stat(b); err2 == nil {
			return os.SameFile(sa, sb)
		}
	}
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 == nil && err2 == nil {
		aa, bb = filepath.Clean(aa), filepath.Clean(bb)
		if runtime.GOOS == "windows" {
			return strings.EqualFold(aa, bb)
		}
		return aa == bb
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// isPublicIP 判断是否为可写入公网 DNS 的地址，拒绝私网、回环、链路本地、CGNAT 与保留网段。
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return false
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 CGNAT
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // TEST-NET-1
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // TEST-NET-2
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // TEST-NET-3
			return false
		case v4[0] >= 224: // 组播与保留
			return false
		}
		return true
	}
	if v6 := ip.To16(); v6 != nil {
		if v6[0]&0xfe == 0xfc { // fc00::/7 ULA
			return false
		}
		return true
	}
	return false
}

func due(last string, d time.Duration) bool {
	if last == "" {
		return true
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", last, time.Local)
	if err != nil {
		return true
	}
	return time.Since(t) >= d
}
