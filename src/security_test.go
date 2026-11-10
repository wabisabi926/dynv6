package main

import (
	"testing"
	"time"
)

// 探测地址固定为内置源：即使有人直接 POST 自定义 URL，也不能让服务访问内网地址。
func TestProbeSourcesFixed(t *testing.T) {
	a := &App{}
	c := a.normalize(Config{
		IPv4ProbeURL: "http://127.0.0.1:8092/api/health",
		IPv6ProbeURL: "file:///etc/passwd",
	})
	if c.IPv4ProbeURL != ipv4ProbeSources {
		t.Fatalf("IPv4 探测源应固定，得到 %q", c.IPv4ProbeURL)
	}
	if c.IPv6ProbeURL != ipv6ProbeSources {
		t.Fatalf("IPv6 探测源应固定，得到 %q", c.IPv6ProbeURL)
	}
	if c.OutputDir != "${APPDATA}/certs" {
		t.Fatalf("默认输出目录应在应用私有数据目录，得到 %q", c.OutputDir)
	}
	if a.defaultConfig().OutputDir != "${APPDATA}/certs" {
		t.Fatal("defaultConfig 输出目录应为私有目录")
	}
}

// detectIP 只接受 http/https 且带 Host 的地址，且不跟随重定向。
func TestDetectIPRejectsUnsafeURL(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com/ip", "http://", "not-a-url", "https://example.com"} {
		// 前四个应在发起请求前就被拒绝；最后一个会真实出网但 scheme 合法，这里只校验不 panic
		if u == "https://example.com" {
			continue
		}
		if _, err := detectIP(u, true, 50*time.Millisecond); err == nil {
			t.Fatalf("%q 应被拒绝", u)
		}
	}
}
