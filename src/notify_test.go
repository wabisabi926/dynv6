package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendTelegram(t *testing.T) {
	var gotChat, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot123:abc/sendMessage" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = r.ParseForm()
		gotChat = r.Form.Get("chat_id")
		gotText = r.Form.Get("text")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	old := tgAPIBase
	tgAPIBase = srv.URL
	defer func() { tgAPIBase = old }()

	a := &App{}
	c := Config{TGEnabled: true, TGBotToken: "123:abc", TGChatID: "42"}
	if err := a.sendTelegram(c, "<b>hello</b>"); err != nil {
		t.Fatalf("sendTelegram: %v", err)
	}
	if gotChat != "42" {
		t.Fatalf("chat_id = %q, want 42", gotChat)
	}
	if gotText != "<b>hello</b>" {
		t.Fatalf("text = %q", gotText)
	}
}
