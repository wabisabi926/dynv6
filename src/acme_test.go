package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadConfValue(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.conf")
	content := "Le_Domain='a.example.com'\nLe_API='https://acme-v02.api.letsencrypt.org/directory'\nLe_Alt=\"*.a.example.com\"\n"
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readConfValue(p, "Le_Domain"); got != "a.example.com" {
		t.Fatalf("Le_Domain = %q", got)
	}
	if got := readConfValue(p, "Le_API"); got != caServerLE {
		t.Fatalf("Le_API = %q", got)
	}
	if got := readConfValue(p, "Le_Alt"); got != "*.a.example.com" {
		t.Fatalf("Le_Alt = %q (双引号未去除)", got)
	}
	if got := readConfValue(p, "Nope"); got != "" {
		t.Fatalf("缺失 key 应返回空，得到 %q", got)
	}
	if got := readConfValue(filepath.Join(dir, "missing.conf"), "Le_API"); got != "" {
		t.Fatalf("文件不存在应返回空，得到 %q", got)
	}
}

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

// acme.sh 用 <domain>_ecc 或 <domain> 两种目录保存域名配置，两种都要能找到
func TestCertConfPath(t *testing.T) {
	home := t.TempDir()
	a := &App{paths: Paths{Var: t.TempDir()}, lastNotify: map[string]time.Time{}}
	c := Config{Domain: "a.example.com", AcmeHome: home, KeyLength: "ec-256"}

	if got := a.certConfPath(c); got != "" {
		t.Fatalf("未签发时应返回空，得到 %q", got)
	}
	eccDir := filepath.Join(home, "a.example.com_ecc")
	if err := os.MkdirAll(eccDir, 0700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(eccDir, "a.example.com.conf")
	if err := os.WriteFile(conf, []byte("Le_API='"+caServerLETest+"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := a.certConfPath(c); got != conf {
		t.Fatalf("应找到 ecc 配置，得到 %q", got)
	}
}

func TestClassifyAcmeError(t *testing.T) {
	cases := []struct {
		out  string
		want string
	}{
		{"Could not find a matching zone for _acme-challenge.x.dynv6.net. Maybe your HTTP Token is not authorized to access the zone", "HTTP Token 无权访问该域名（zone）"},
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

// 用户主动删空分发目标（显式 []）后不能又被补回来；缺字段（nil）才补默认值
func TestNormalizeTargets(t *testing.T) {
	a := &App{paths: Paths{Var: t.TempDir()}}
	if got := a.normalize(Config{}); len(got.Targets) == 0 {
		t.Fatal("缺 targets 字段的老配置应补默认目标")
	}
	if got := a.normalize(Config{Schema: 2, Targets: []Target{}}); len(got.Targets) != 0 {
		t.Fatalf("显式空数组不应补默认目标，得到 %d 个", len(got.Targets))
	}
	// 目录为空的启用目标要自动关闭
	got := a.normalize(Config{Schema: 2, Targets: []Target{{ID: "x", Kind: "emby", Enabled: true, Dir: "", Filename: "a.pfx"}}})
	if got.Targets[0].Enabled {
		t.Fatal("空目录目标应被自动禁用")
	}
	if got.Targets[0].Mode != "0644" {
		t.Fatalf("目标权限应固定 0644，得到 %q", got.Targets[0].Mode)
	}
}
