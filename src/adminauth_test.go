package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminPasswordHash(t *testing.T) {
	hash, err := hashAdminPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if !verifyAdminPassword(hash, "secret123") {
		t.Fatal("正确密码应校验通过")
	}
	if verifyAdminPassword(hash, "secret124") {
		t.Fatal("错误密码不应校验通过")
	}
	if verifyAdminPassword("bad", "secret123") {
		t.Fatal("损坏的哈希不应校验通过")
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
}

func TestAdminSetupLoginFlow(t *testing.T) {
	dir := t.TempDir()
	a := newApp(Paths{AuthFile: filepath.Join(dir, "admin.json")}, false)
	h := a.handler()

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/auth/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth status = %d", rec.Code)
	}
	var status map[string]any
	decodeJSON(t, rec, &status)
	if status["setupRequired"] != true || status["authenticated"] != false {
		t.Fatalf("首次启动状态不对: %+v", status)
	}

	body := `{"username":"admin","password":"secret123"}`
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/setup/admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "dynv6")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup = %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup 应设置登录 Cookie")
	}
	var session *http.Cookie
	for _, c := range cookies {
		if c.Name == adminCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatal("没有管理员会话 Cookie")
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/config", nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("带会话访问配置 = %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/config", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("未登录访问配置应 403，得到 %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/auth/logout", nil)
	req.AddCookie(session)
	req.Header.Set("X-Requested-With", "dynv6")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}

	loginBody := `{"username":"admin","password":"secret123"}`
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/auth/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "dynv6")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/auth/status", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	decodeJSON(t, rec, &status)
	if status["authenticated"] != true {
		t.Fatalf("登录后应 authenticated: %+v", status)
	}
}

func TestAdminBrokenFailClosed(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "admin.json")
	if err := os.WriteFile(authFile, []byte("{broken-json"), 0600); err != nil {
		t.Fatal(err)
	}
	a := newApp(Paths{AuthFile: authFile}, false)
	h := a.handler()

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/auth/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var status map[string]any
	decodeJSON(t, rec, &status)
	if status["adminBroken"] != true {
		t.Fatalf("损坏的 admin.json 应返回 adminBroken: %+v", status)
	}
	if status["setupRequired"] != false {
		t.Fatalf("损坏后不应允许重新初始化: %+v", status)
	}

	body := `{"username":"admin","password":"secret123"}`
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/setup/admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "dynv6")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("损坏后 setup 应拒绝，实际 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginKeysPerAccountAndIP(t *testing.T) {
	local := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/auth/login", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	keys := loginKeys(local, "Admin")
	if len(keys) != 1 || keys[0] != "user:admin" {
		t.Fatalf("本机登录只应按账号计数: %v", keys)
	}

	remote := httptest.NewRequest(http.MethodPost, "http://203.0.113.5/api/auth/login", nil)
	remote.RemoteAddr = "203.0.113.5:1234"
	keys = loginKeys(remote, "admin")
	if len(keys) != 2 {
		t.Fatalf("远端登录应同时按账号和 IP 计数: %v", keys)
	}
}
