package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	adminCookieName   = "dynv6_admin"
	adminSessionTTL   = 7 * 24 * time.Hour
	pbkdf2Iterations  = 120000
	pbkdf2KeyLen      = 32
	pbkdf2SaltLen     = 16
	loginMaxFailures  = 5
	loginLockDuration = 5 * time.Minute
	adminUsernameMax  = 32
	adminUsernameMin  = 3
	adminPasswordMin  = 8
	adminPasswordMax  = 128
)

type AdminAuth struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type adminSession struct {
	Username  string
	ExpiresAt time.Time
}

type loginAttempt struct {
	Count int
	Until time.Time
}

type authStatusInfo struct {
	Authenticated bool
	SetupRequired bool
	Gateway       bool
	Admin         bool
	AuthDisabled  bool
	AdminBroken   bool
	Username      string
}

var errCurrentPassword = errors.New("当前密码错误")

func (a *App) loadAdminAuth() {
	if a.paths.AuthFile == "" {
		return
	}
	data, err := os.ReadFile(a.paths.AuthFile)
	if err != nil {
		if !os.IsNotExist(err) {
			// 文件存在但读不了：禁止重新初始化，避免无法读取时被他人接管
			a.authBroken = true
			a.log("读取管理员配置失败（已锁定初始化）: %v；请检查文件权限或删除 %s 后重启", err, a.paths.AuthFile)
		}
		return
	}
	var auth AdminAuth
	if err := json.Unmarshal(data, &auth); err != nil {
		a.authBroken = true
		a.log("管理员配置损坏（已锁定初始化）: %v；请删除 %s 后重启重新创建管理员", err, a.paths.AuthFile)
		return
	}
	if auth.Username == "" || auth.PasswordHash == "" || !strings.HasPrefix(auth.PasswordHash, "pbkdf2-sha256$") {
		a.authBroken = true
		a.log("管理员配置无效（已锁定初始化）；请删除 %s 后重启重新创建管理员", a.paths.AuthFile)
		return
	}
	a.authMu.Lock()
	a.admin = auth
	a.authMu.Unlock()
}

func (a *App) hasAdmin() bool {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	return a.admin.Username != "" && a.admin.PasswordHash != ""
}

func (a *App) adminUsername() string {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	return a.admin.Username
}

func (a *App) setAdmin(username, password string) (bool, error) {
	hash, err := hashAdminPassword(password)
	if err != nil {
		return false, err
	}
	next := AdminAuth{Username: username, PasswordHash: hash, UpdatedAt: nowISO()}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false, err
	}
	// 哈希在锁外完成，写入与“是否已初始化”检查在同一把锁内，避免并发 setup 覆盖
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if a.admin.Username != "" && a.admin.PasswordHash != "" {
		return false, nil
	}
	if err := atomicWrite(a.paths.AuthFile, data, 0600); err != nil {
		return false, err
	}
	a.admin = next
	a.sessions = map[string]adminSession{}
	return true, nil
}

func (a *App) verifyAdmin(username, password string) bool {
	a.authMu.Lock()
	auth := a.admin
	a.authMu.Unlock()
	if auth.Username == "" || auth.PasswordHash == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(auth.Username)) != 1 {
		return false
	}
	return verifyAdminPassword(auth.PasswordHash, password)
}

func (a *App) changeAdminPassword(current, next string) error {
	a.authMu.Lock()
	auth := a.admin
	if auth.Username == "" || auth.PasswordHash == "" {
		a.authMu.Unlock()
		return errors.New("管理员账号尚未初始化")
	}
	if !verifyAdminPassword(auth.PasswordHash, current) {
		a.authMu.Unlock()
		return errCurrentPassword
	}
	hash, err := hashAdminPassword(next)
	if err != nil {
		a.authMu.Unlock()
		return err
	}
	nextAuth := AdminAuth{Username: auth.Username, PasswordHash: hash, UpdatedAt: nowISO()}
	data, err := json.MarshalIndent(nextAuth, "", "  ")
	if err == nil {
		err = atomicWrite(a.paths.AuthFile, data, 0600)
	}
	if err != nil {
		a.authMu.Unlock()
		return err
	}
	a.admin = nextAuth
	a.sessions = map[string]adminSession{}
	a.authMu.Unlock()
	return nil
}

func hashAdminPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	saltText := base64.RawStdEncoding.EncodeToString(salt)
	keyText := base64.RawStdEncoding.EncodeToString(key)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, saltText, keyText), nil
}

func verifyAdminPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 1000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var blockIndex [4]byte
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(blockIndex[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func normalizeAdminUsername(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "admin"
	}
	return s
}

func validAdminUsername(s string) bool {
	if len([]rune(s)) < adminUsernameMin || len([]rune(s)) > adminUsernameMax {
		return false
	}
	allDigits := true
	for i, r := range s {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
		if r < '0' || r > '9' {
			allDigits = false
		}
	}
	return !allDigits
}

func validAdminPassword(s string) bool {
	if len(s) < adminPasswordMin || len(s) > adminPasswordMax {
		return false
	}
	return !strings.EqualFold(s, "admin")
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (a *App) createAdminSession(username string) (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	a.authMu.Lock()
	if a.sessions == nil {
		a.sessions = map[string]adminSession{}
	}
	now := time.Now()
	for key, session := range a.sessions {
		if now.After(session.ExpiresAt) {
			delete(a.sessions, key)
		}
	}
	a.sessions[token] = adminSession{Username: username, ExpiresAt: now.Add(adminSessionTTL)}
	a.authMu.Unlock()
	return token, nil
}

func adminSessionToken(r *http.Request) string {
	if c, err := r.Cookie(adminCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

func (a *App) adminSession(r *http.Request) (string, bool) {
	token := adminSessionToken(r)
	if token == "" {
		return "", false
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	session, ok := a.sessions[token]
	if !ok {
		return "", false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(a.sessions, token)
		return "", false
	}
	return session.Username, true
}

func (a *App) sessionValid(r *http.Request) bool {
	_, ok := a.adminSession(r)
	return ok
}

func (a *App) revokeAdminSession(r *http.Request) {
	token := adminSessionToken(r)
	if token == "" {
		return
	}
	a.authMu.Lock()
	delete(a.sessions, token)
	a.authMu.Unlock()
}

func (a *App) setAdminCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(adminSessionTTL / time.Second),
	})
}

func (a *App) clearAdminCookie(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *App) gatewayUser(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Trim-Username"))
}

func (a *App) gatewayAdmin(r *http.Request) bool {
	if a.gatewayUser(r) == "" {
		return false
	}
	raw := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Trim-Isadmin")))
	return raw == "true" || raw == "1"
}

func (a *App) authStatus(r *http.Request) authStatusInfo {
	if a.authDisabled {
		return authStatusInfo{Authenticated: true, Admin: a.isAdminQuiet(r), AuthDisabled: true, Username: "admin"}
	}
	if user := a.gatewayUser(r); user != "" {
		return authStatusInfo{Authenticated: true, Gateway: true, Admin: a.gatewayAdmin(r), Username: user}
	}
	if username, ok := a.adminSession(r); ok {
		return authStatusInfo{Authenticated: true, Admin: true, Username: username}
	}
	if a.authBroken {
		return authStatusInfo{AdminBroken: true}
	}
	return authStatusInfo{SetupRequired: !a.hasAdmin()}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// loginKeys 使用“账号 + 来源 IP”双维度：
//   - 账号维度 5 次失败锁定，防止针对某个账号爆破；
//   - IP 维度阈值更高，只限制同一来源批量试账号；
//   - 回环/Unix Socket（反向代理、飞牛网关）不加 IP 限制，避免一个人输错锁死所有人。
func loginKeys(r *http.Request, username string) []string {
	keys := []string{"user:" + strings.ToLower(strings.TrimSpace(username))}
	if ip := remoteIP(r); ip != "" {
		if parsed := net.ParseIP(ip); parsed == nil || !parsed.IsLoopback() {
			keys = append(keys, "ip:"+ip)
		}
	}
	return keys
}

func loginLimit(key string) int {
	if strings.HasPrefix(key, "ip:") {
		return loginMaxFailures * 4
	}
	return loginMaxFailures
}

func (a *App) allowLogin(keys []string) (bool, time.Duration) {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if a.loginGuard == nil {
		a.loginGuard = map[string]loginAttempt{}
	}
	var retry time.Duration
	now := time.Now()
	for _, key := range keys {
		attempt := a.loginGuard[key]
		if attempt.Until.After(now) {
			if wait := time.Until(attempt.Until); wait > retry {
				retry = wait
			}
			continue
		}
		if !attempt.Until.IsZero() {
			delete(a.loginGuard, key)
		}
	}
	if retry > 0 {
		return false, retry
	}
	return true, 0
}

func (a *App) failLogin(keys []string) {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if a.loginGuard == nil {
		a.loginGuard = map[string]loginAttempt{}
	}
	for _, key := range keys {
		attempt := a.loginGuard[key]
		attempt.Count++
		if attempt.Count >= loginLimit(key) {
			attempt.Until = time.Now().Add(loginLockDuration)
			attempt.Count = 0
		}
		a.loginGuard[key] = attempt
	}
}

func (a *App) resetLogin(keys []string) {
	a.authMu.Lock()
	for _, key := range keys {
		delete(a.loginGuard, key)
	}
	a.authMu.Unlock()
}

func writeAuthError(w http.ResponseWriter, code int, key, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	payload := map[string]any{"ok": false, "error": msg}
	if key != "" {
		payload["code"] = key
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *App) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	status := a.authStatus(r)
	writeJSON(w, map[string]any{
		"ok":            true,
		"authenticated": status.Authenticated,
		"setupRequired": status.SetupRequired,
		"gateway":       status.Gateway,
		"admin":         status.Admin,
		"username":      status.Username,
		"authDisabled":  status.AuthDisabled,
		"adminBroken":   status.AdminBroken,
	})
}

func (a *App) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	status := a.authStatus(r)
	writeJSON(w, map[string]any{"ok": true, "required": status.SetupRequired})
}

func (a *App) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !a.checkCSRF(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
		return
	}
	if a.authDisabled {
		writeAuthError(w, http.StatusConflict, "AUTH_DISABLED", "管理员账号鉴权已被环境变量禁用")
		return
	}
	if user := a.gatewayUser(r); user != "" && !a.gatewayAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	if a.authBroken {
		writeAuthError(w, http.StatusInternalServerError, "ADMIN_BROKEN", "管理员配置损坏，请删除数据目录下的 admin.json 后重启应用")
		return
	}
	if a.hasAdmin() {
		writeAuthError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETED", "管理员账号已初始化")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	username := normalizeAdminUsername(req.Username)
	if !validAdminUsername(username) {
		writeErr(w, http.StatusBadRequest, "用户名需为 3-32 位，只能包含字母、数字、下划线和短横线，且不能是纯数字")
		return
	}
	if !validAdminPassword(req.Password) {
		writeErr(w, http.StatusBadRequest, "密码至少 8 位，且不能使用 admin")
		return
	}
	ok, err := a.setAdmin(username, req.Password)
	if err != nil {
		a.log("保存管理员账号失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "保存管理员账号失败")
		return
	}
	if !ok {
		writeAuthError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETED", "管理员账号已初始化")
		return
	}
	token, err := a.createAdminSession(username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "初始化成功，请返回登录页登录")
		return
	}
	a.setAdminCookie(w, r, token)
	a.resetLogin(loginKeys(r, username))
	a.log("管理员账号已初始化: %s", username)
	writeJSON(w, map[string]any{"ok": true, "message": "初始化成功", "token": token, "username": username})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !a.checkCSRF(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
		return
	}
	if a.authDisabled {
		writeAuthError(w, http.StatusConflict, "AUTH_DISABLED", "管理员账号鉴权已被环境变量禁用")
		return
	}
	if !a.hasAdmin() {
		if a.authBroken {
			writeAuthError(w, http.StatusInternalServerError, "ADMIN_BROKEN", "管理员配置损坏，请删除数据目录下的 admin.json 后重启应用")
			return
		}
		writeAuthError(w, http.StatusConflict, "SETUP_REQUIRED", "首次启动尚未创建管理员账号，请先完成初始化")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	username := strings.TrimSpace(req.Username)
	keys := loginKeys(r, username)
	if ok, retry := a.allowLogin(keys); !ok {
		secs := int(retry.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, http.StatusTooManyRequests, "登录失败次数过多，请稍后再试")
		return
	}
	if !a.verifyAdmin(username, req.Password) {
		a.failLogin(keys)
		writeErr(w, http.StatusUnauthorized, "账号或密码错误")
		return
	}
	a.resetLogin(keys)
	token, err := a.createAdminSession(username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "令牌生成失败")
		return
	}
	a.setAdminCookie(w, r, token)
	a.log("管理员登录成功: %s", username)
	writeJSON(w, map[string]any{"ok": true, "message": "登录成功", "token": token, "username": username})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !a.checkCSRF(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
		return
	}
	a.revokeAdminSession(r)
	a.clearAdminCookie(w, r)
	writeJSON(w, map[string]any{"ok": true, "message": "已退出登录"})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !a.checkCSRF(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
		return
	}
	if a.authDisabled {
		writeAuthError(w, http.StatusConflict, "AUTH_DISABLED", "管理员账号鉴权已被环境变量禁用")
		return
	}
	if !a.sessionValid(r) {
		writeErr(w, http.StatusForbidden, "请先使用本地管理员账号登录")
		return
	}
	keys := loginKeys(r, a.adminUsername())
	if ok, retry := a.allowLogin(keys); !ok {
		secs := int(retry.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !validAdminPassword(req.NewPassword) {
		writeErr(w, http.StatusBadRequest, "新密码至少 8 位，且不能使用 admin")
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		writeErr(w, http.StatusBadRequest, "两次输入的新密码不一致")
		return
	}
	if err := a.changeAdminPassword(req.CurrentPassword, req.NewPassword); err != nil {
		if errors.Is(err, errCurrentPassword) {
			a.failLogin(keys)
			writeErr(w, http.StatusUnauthorized, "当前密码错误")
			return
		}
		a.log("修改管理员密码失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	a.resetLogin(keys)
	token, err := a.createAdminSession(a.adminUsername())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "密码已修改，请重新登录")
		return
	}
	a.setAdminCookie(w, r, token)
	writeJSON(w, map[string]any{"ok": true, "message": "密码修改成功"})
}
