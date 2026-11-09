package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDynv6DNSPresentAndCleanup(t *testing.T) {
	var created, deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 11, "name": "example.com"}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/11/records":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["name"] != "_acme-challenge.sub" || body["type"] != "TXT" || body["data"] == "" {
				t.Errorf("记录内容不正确: %v", body)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 22})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/11/records/22":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("未预期的请求 %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	d := newDynv6DNS("test-token", 0)
	d.base = srv.URL
	d.client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}
	if err := d.Present("sub.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("Present 失败: %v", err)
	}
	if !created {
		t.Fatal("应创建 TXT 记录")
	}
	if err := d.CleanUp("sub.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("CleanUp 失败: %v", err)
	}
	if !deleted {
		t.Fatal("应删除 TXT 记录")
	}
}

func TestDynv6DNSZoneNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 11, "name": "other.com"}})
	}))
	defer srv.Close()

	d := newDynv6DNS("test-token", 0)
	d.base = srv.URL
	d.client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	if err := d.Present("sub.example.com", "token", "key-auth"); err == nil {
		t.Fatal("域名不在 Token 权限内时应返回错误")
	}
}
