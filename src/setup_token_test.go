package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newSetupTokenApp(t *testing.T) *App {
	dir := t.TempDir()
	return &App{
		paths:      Paths{Listen: "0.0.0.0:8092", Var: dir, AuthFile: filepath.Join(dir, "admin.json")},
		laneBusy:   map[string]bool{},
		lastNotify: map[string]time.Time{},
		sessions:   map[string]adminSession{},
		loginGuard: map[string]loginAttempt{},
	}
}

func postSetup(h http.Handler, token string) *httptest.ResponseRecorder {
	body := `{"username":"adminuser","password":"StrongPass123!","setupToken":"` + token + `"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/setup/admin", strings.NewReader(body))
	req.Header.Set("X-Requested-With", "dynv6")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// 回环来源（飞牛网关反代、本机浏览器）免 setup token；局域网直连仍必须携带
func TestSetupTokenLoopbackExemption(t *testing.T) {
	a := newSetupTokenApp(t)
	a.initSetupToken()
	h := a.handler()

	mkReq := func(remote, token string) *http.Request {
		body := `{"username":"adminuser","password":"StrongPass123!","setupToken":"` + token + `"}`
		req := httptest.NewRequest(http.MethodPost, "http://example.com/api/setup/admin", strings.NewReader(body))
		req.RemoteAddr = remote
		req.Header.Set("X-Requested-With", "dynv6")
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	// 局域网直连（非回环）：无令牌 403
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mkReq("192.168.50.100:52341", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("局域网直连无令牌应 403，得到 %d", rec.Code)
	}
	// 局域网直连：错误令牌 403
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mkReq("192.168.50.100:52341", "wrong"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("局域网直连错误令牌应 403，得到 %d", rec.Code)
	}
	// 回环来源（网关反代）：免令牌直接初始化成功
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mkReq("127.0.0.1:41000", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("回环来源应免令牌初始化成功，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if a.setupToken != "" {
		t.Fatal("初始化成功后应清空令牌")
	}
}

func TestSetupTokenRequiredInServiceMode(t *testing.T) {
	a := newSetupTokenApp(t)
	a.initSetupToken()
	if a.setupToken == "" {
		t.Fatal("服务模式首次启动应生成初始化令牌")
	}
	tokenPath := filepath.Join(a.paths.Var, "setup-token")
	data, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(data)) != a.setupToken {
		t.Fatalf("setup-token 内容应与令牌一致: %v", err)
	}

	h := a.handler()
	if rec := postSetup(h, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("缺少初始化令牌应 403，得到 %d", rec.Code)
	}
	if rec := postSetup(h, "wrong-token"); rec.Code != http.StatusForbidden {
		t.Fatalf("错误初始化令牌应 403，得到 %d", rec.Code)
	}
	if rec := postSetup(h, a.setupToken); rec.Code != http.StatusOK {
		t.Fatalf("正确初始化令牌应 200，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if a.setupToken != "" {
		t.Fatal("初始化成功后应清空令牌")
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("初始化成功后应删除 setup-token 文件")
	}
}

func TestSetupTokenNotNeededLocally(t *testing.T) {
	// 本地回环 TCP 模式与 Unix Socket 模式由一次性令牌 / SO_PEERCRED 保护，无需 setup token
	for _, p := range []Paths{
		{DevPort: "8092"},
		{Socket: "/tmp/dynv6.sock"},
	} {
		a := newSetupTokenApp(t)
		a.paths.Listen = ""
		a.paths.DevPort = p.DevPort
		a.paths.Socket = p.Socket
		a.initSetupToken()
		if a.setupToken != "" {
			t.Fatalf("本地模式不应生成 setup token: %+v", a.paths)
		}
	}
	// 已有管理员账号时不再生成
	a := newSetupTokenApp(t)
	a.admin = AdminAuth{Username: "admin", PasswordHash: "pbkdf2-sha256$1$abc"}
	a.initSetupToken()
	if a.setupToken != "" {
		t.Fatal("已初始化的实例不应再生成 setup token")
	}
}
