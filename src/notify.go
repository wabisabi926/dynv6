package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tgResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

var tgAPIBase = "https://api.telegram.org"

func (a *App) telegramReady(c Config) bool {
	return c.TGEnabled && strings.TrimSpace(c.TGBotToken) != "" && strings.TrimSpace(c.TGChatID) != ""
}

func (a *App) telegramClient(c Config) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if strings.TrimSpace(c.TGProxyURL) != "" {
		if u, err := url.Parse(c.TGProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: tr}
}

func (a *App) sendTelegram(c Config, text string) error {
	if !a.telegramReady(c) {
		return fmt.Errorf("Telegram 未启用，或 Bot Token / Chat ID 为空")
	}
	if len([]rune(text)) > 4096 {
		text = string([]rune(text)[:4096])
	}
	form := url.Values{}
	form.Set("chat_id", c.TGChatID)
	form.Set("text", text)
	form.Set("parse_mode", "HTML")
	form.Set("disable_web_page_preview", "true")
	endpoint := tgAPIBase + "/bot" + c.TGBotToken + "/sendMessage"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.telegramClient(c).Do(req)
	if err != nil {
		return fmt.Errorf("调用 Telegram 失败: %s", maskSecrets(err.Error(), a.secrets(c)))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out tgResponse
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || !out.OK {
		desc := out.Description
		if desc == "" {
			desc = strings.TrimSpace(string(body))
		}
		return fmt.Errorf("Telegram 返回 HTTP %d: %s", resp.StatusCode, maskSecrets(desc, a.secrets(c)))
	}
	return nil
}

// notify 异步发送 Telegram 通知；未配置时静默跳过，绝不阻塞任务
func (a *App) notify(title, body string) {
	c := a.getConfig()
	if !a.telegramReady(c) {
		return
	}
	key := title + "|" + body
	a.notifyMu.Lock()
	if a.lastNotify == nil {
		a.lastNotify = map[string]time.Time{}
	}
	if last, ok := a.lastNotify[key]; ok && time.Since(last) < 10*time.Minute {
		a.notifyMu.Unlock()
		return
	}
	a.lastNotify[key] = time.Now()
	a.notifyMu.Unlock()
	text := "<b>" + html.EscapeString(title) + "</b>"
	if body != "" {
		text += "\n" + html.EscapeString(body)
	}
	go func() {
		if err := a.sendTelegram(c, text); err != nil {
			a.log("Telegram 通知失败: %v", err)
		}
	}()
}

func (a *App) testTelegram(c Config) error {
	return a.sendTelegram(c, "<b>Dynv6 管家测试消息</b>\n如果你看到这条消息，说明 Telegram 通知配置正确。")
}
