package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsValidDomain(t *testing.T) {
	valid := []string{"example.com", "a-b.example.com", "xn--fiqs8s.com", "Example.COM"}
	for _, s := range valid {
		if !isValidDomain(s) {
			t.Fatalf("%q 应该合法", s)
		}
	}
	invalid := []string{"", "example", "*.example.com", "-a.com", "a-.com", "a..com", "a_b.com", "a\n.com", strings.Repeat("a", 64) + ".com"}
	for _, s := range invalid {
		if isValidDomain(s) {
			t.Fatalf("%q 应该不合法", s)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"1.1.1.1":              true,
		"10.0.0.1":             false,
		"192.168.1.1":          false,
		"127.0.0.1":            false,
		"100.64.0.1":           false,
		"169.254.1.1":          false,
		"224.0.0.1":            false,
		"2606:4700:4700::1111": true,
		"fc00::1":              false,
		"fe80::1":              false,
		"::1":                  false,
	}
	for raw, want := range cases {
		if got := isPublicIP(net.ParseIP(raw)); got != want {
			t.Fatalf("isPublicIP(%s) = %v，期望 %v", raw, got, want)
		}
	}
}

func TestDdnsNeedsUpdate(t *testing.T) {
	st := State{LastDDNSDomain: "a.example.com", LastDDNSTokenHash: "abc", LastIPv4: "1.2.3.4"}
	c := Config{Domain: "a.example.com"}
	if changed, _ := ddnsNeedsUpdate(st, c, "1.2.3.4", "", "abc", false); changed {
		t.Fatal("IP/域名/Token 都没变，不应更新")
	}
	if changed, _ := ddnsNeedsUpdate(st, c, "1.2.3.5", "", "abc", false); !changed {
		t.Fatal("IPv4 变化应更新")
	}
	c.Domain = "b.example.com"
	if changed, _ := ddnsNeedsUpdate(st, c, "1.2.3.4", "", "abc", false); !changed {
		t.Fatal("域名变化应更新")
	}
	c.Domain = "a.example.com"
	if changed, _ := ddnsNeedsUpdate(st, c, "1.2.3.4", "", "def", false); !changed {
		t.Fatal("Token 变化应更新")
	}
	if changed, _ := ddnsNeedsUpdate(st, c, "1.2.3.4", "", "abc", true); !changed {
		t.Fatal("force 应更新")
	}
}

func TestNeedsDeploy(t *testing.T) {
	c := Config{CA: "letsencrypt"}
	st := State{LastIssueAt: "2026-01-01 00:00:01", CertCA: "letsencrypt"}
	if !needsDeploy(st, c) {
		t.Fatal("签发后未分发应需要重试")
	}
	st.LastDeployAt = "2026-01-01 00:00:02"
	if needsDeploy(st, c) {
		t.Fatal("分发时间晚于签发时间不应重试")
	}
	st.CertCA = "letsencrypt_test"
	if needsDeploy(st, c) {
		t.Fatal("磁盘上是测试证书、配置是正式机构时不应重试分发")
	}
}

func TestValidateManagedPaths(t *testing.T) {
	root := t.TempDir()
	a := &App{paths: Paths{Var: root, Etc: root, Dest: root, Share: filepath.Join(root, "share")}}
	c := Config{
		OutputDir: filepath.Join(root, "out"),
		BackupDir: filepath.Join(root, "backup"),
		AcmeHome:  filepath.Join(root, "acme"),
	}
	if err := a.validateManagedPaths(c); err != nil {
		t.Fatalf("合法路径不应报错: %v", err)
	}
	c.OutputDir = "relative/path"
	if err := a.validateManagedPaths(c); err == nil {
		t.Fatal("相对路径应报错")
	}
	c.OutputDir = root + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escape"
	if err := a.validateManagedPaths(c); err == nil {
		t.Fatal("包含 .. 的路径应报错")
	}
	c.OutputDir = "${UNKNOWN}/certs"
	if err := a.validateManagedPaths(c); err == nil {
		t.Fatal("未知变量应报错")
	}
}

func TestHasDotDot(t *testing.T) {
	bad := []string{"/vol1/../etc", "..", "/vol1/1000/..", `C:\certs\..\windows`}
	for _, p := range bad {
		if !hasDotDot(p) {
			t.Fatalf("%q 应判定为包含 .. 路径段", p)
		}
	}
	good := []string{"/vol1/1000/certs", "/vol1/a..b/certs", "C:\\certs\\a..b", "/vol1/.../x"}
	for _, p := range good {
		if hasDotDot(p) {
			t.Fatalf("%q 不应被误判", p)
		}
	}
}

func TestNormalizeAllowsZeroDNSSleep(t *testing.T) {
	a := newApp(Paths{AuthFile: filepath.Join(t.TempDir(), "admin.json")}, false)
	if got := a.normalize(Config{DNSSleep: 0}).DNSSleep; got != 0 {
		t.Fatalf("dns_sleep=0 应保持 0，实际 %d", got)
	}
	if got := a.normalize(Config{DNSSleep: -1}).DNSSleep; got != 120 {
		t.Fatalf("负数应回退默认 120，实际 %d", got)
	}
}
