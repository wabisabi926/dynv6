package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTXTStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	fqdn := "_acme-challenge.sub.example.com"
	path := filepath.Join(dir, "pending-txt.json")

	s := newTXTStore(dir)
	s.add(fqdn, "11", "22")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("创建 TXT 后应落盘: %v", err)
	}
	// 模拟重启后重新加载
	if got := len(newTXTStore(dir).list(fqdn)); got != 1 {
		t.Fatalf("重启后应仍能读到待清理记录，得到 %d", got)
	}
	if got := len(newTXTStore(dir).stale(time.Hour)); got != 0 {
		t.Fatalf("刚创建的记录不应算超时，得到 %d", got)
	}
	// 人为写入 2 小时前的时间戳，模拟进程被 kill -9 后残留
	old := []pendingTXT{{FQDN: fqdn, ZoneID: "11", RecordID: "22", CreatedAt: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)}}
	data, _ := json.Marshal(old)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if got := len(newTXTStore(dir).stale(time.Hour)); got != 1 {
		t.Fatalf("超时记录应被识别，得到 %d", got)
	}
	newTXTStore(dir).removeByID(fqdn, "11", "22")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("全部清理完成后应删除待清理文件")
	}
}

// DNS 生效等待可被取消；持久化记录仍能在 CleanUp 时删除
func TestDNSWaitCancellableAndPersistedCleanup(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 11, "name": "example.com"}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/11/records":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 22})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/11/records/22":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	d := newDynv6DNS("test-token", 10*time.Second)
	d.base = srv.URL
	d.client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}
	d.store = newTXTStore(dir)
	ch := make(chan struct{})
	d.cancel = ch
	go func() { time.Sleep(50 * time.Millisecond); close(ch) }()

	start := time.Now()
	err := d.Present("sub.example.com", "token", "key-auth")
	if err == nil || !strings.Contains(err.Error(), "取消") {
		t.Fatalf("取消后 Present 应返回取消错误，得到 %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("取消后应立即返回，不能等满 DNSSleep")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "pending-txt.json")); statErr != nil {
		t.Fatal("创建成功的 TXT 必须持久化，即使等待被取消")
	}
	if err := d.CleanUp("sub.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("CleanUp 失败: %v", err)
	}
	if !deleted {
		t.Fatal("CleanUp 应删除持久化记录")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "pending-txt.json")); !os.IsNotExist(statErr) {
		t.Fatal("清理成功后应删除待清理文件")
	}
}

func TestAllowedProxyScheme(t *testing.T) {
	for _, s := range []string{"http", "https", "socks5", "socks5h", "HTTPS"} {
		if !allowedProxyScheme(s) {
			t.Fatalf("%s 应允许", s)
		}
	}
	for _, s := range []string{"file", "ftp", "gopher", ""} {
		if allowedProxyScheme(s) {
			t.Fatalf("%s 应拒绝", s)
		}
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	a := &App{
		paths:      Paths{Listen: "0.0.0.0:8092", Var: t.TempDir()},
		laneBusy:   map[string]bool{},
		lastNotify: map[string]time.Time{},
	}
	rec := httptest.NewRecorder()
	a.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/api/health", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "object-src 'none'") {
		t.Fatalf("应返回 CSP 安全响应头，得到 %q", csp)
	}
}
