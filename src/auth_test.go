package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newLocalTestApp() *App {
	return &App{
		paths:      Paths{DevPort: "8092"},
		localAuth:  true,
		localToken: "test-token-0123456789abcdef",
		laneBusy:   map[string]bool{},
		lastNotify: map[string]time.Time{},
	}
}

// 服务模式（Docker / 反向代理）没有本地令牌，除登录相关接口外必须要求管理员会话。
func TestServerModeRequiresLogin(t *testing.T) {
	a := &App{
		paths:      Paths{Listen: "0.0.0.0:8092", Var: t.TempDir()},
		laneBusy:   map[string]bool{},
		lastNotify: map[string]time.Time{},
	}
	h := a.handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/api/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录访问 /api/status 应 401，得到 %d", rec.Code)
	}

	for _, path := range []string{"/api/health", "/api/auth/status"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 应允许匿名访问，得到 %d", path, rec.Code)
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("首页应允许匿名访问以便登录，得到 %d", rec.Code)
	}
}

// 同时设置 DYNV6_LISTEN 与 DYNV6_DEV_PORT 时，服务模式优先，不能误启用本地令牌。
func TestListenTakesPrecedenceOverDevPort(t *testing.T) {
	t.Setenv("DYNV6_LISTEN", "0.0.0.0:8092")
	t.Setenv("DYNV6_DEV_PORT", "6011")
	t.Setenv("TRIM_APPDEST", "")
	p := detectPaths()
	if p.Listen != "0.0.0.0:8092" || p.DevPort != "" {
		t.Fatalf("服务模式应优先，得到 Listen=%q DevPort=%q", p.Listen, p.DevPort)
	}
}

// 飞牛环境使用官方 service_port 端口模式，与 faststrm 一致，不再走 Unix Socket。
func TestFnosUsesServicePort(t *testing.T) {
	t.Setenv("DYNV6_LISTEN", "")
	t.Setenv("DYNV6_DEV_PORT", "")
	t.Setenv("DYNV6_DOCKER", "")
	t.Setenv("TRIM_APPDEST", t.TempDir())
	p := detectPaths()
	if p.Listen != "0.0.0.0:8092" || p.DevPort != "" {
		t.Fatalf("飞牛应使用 8092 端口模式，得到 Listen=%q DevPort=%q", p.Listen, p.DevPort)
	}
	t.Setenv("DYNV6_PORT", "18092")
	if p := detectPaths(); p.Listen != "0.0.0.0:18092" {
		t.Fatalf("DYNV6_PORT 应覆盖飞牛端口，得到 %q", p.Listen)
	}
}

func TestLocalAuthGate(t *testing.T) {
	a := newLocalTestApp()
	h := a.handler()

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8092/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("无令牌应 403，得到 %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8092/api/status", nil)
	req.AddCookie(&http.Cookie{Name: localTokenCookie, Value: a.localToken})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("带令牌应 200，得到 %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://evil.example/api/status", nil)
	req.AddCookie(&http.Cookie{Name: localTokenCookie, Value: a.localToken})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("非本机 Host 应 403，得到 %d", rec.Code)
	}
}

func TestLocalTokenRedirect(t *testing.T) {
	a := newLocalTestApp()
	h := a.handler()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8092/?token="+a.localToken, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("有效令牌应 303，得到 %d", rec.Code)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("应设置本地令牌 Cookie")
	}
}

func TestCSRFGate(t *testing.T) {
	a := newLocalTestApp()
	h := a.handler()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8092/api/config", nil)
	req.AddCookie(&http.Cookie{Name: localTokenCookie, Value: a.localToken})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("缺少 X-Requested-With 应 403，得到 %d", rec.Code)
	}
}
