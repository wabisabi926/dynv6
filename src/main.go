package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var Version = "1.0.0"

func detectPaths() Paths {
	cwd, _ := os.Getwd()
	dest := envOr("DYNV6_DATA_DIR", os.Getenv("TRIM_APPDEST"))
	if dest == "" {
		if runtime.GOOS == "windows" {
			if la := os.Getenv("LOCALAPPDATA"); la != "" {
				dest = filepath.Join(la, "dynv6")
			}
		}
		if dest == "" {
			dest = filepath.Join(cwd, ".dev")
		}
	}
	etc := envOr("TRIM_PKGETC", filepath.Join(dest, "etc"))
	varDir := envOr("TRIM_PKGVAR", filepath.Join(dest, "var"))
	var shares []string
	for _, s := range filepath.SplitList(os.Getenv("TRIM_DATA_SHARE_PATHS")) {
		if s = strings.TrimSpace(s); s != "" {
			shares = append(shares, s)
		}
	}
	var accessible []string
	for _, s := range filepath.SplitList(os.Getenv("TRIM_DATA_ACCESSIBLE_PATHS")) {
		if s = strings.TrimSpace(s); s != "" {
			accessible = append(accessible, s)
		}
	}
	share := filepath.Join(varDir, "certs")
	if len(shares) > 0 {
		share = shares[0]
	}
	// 飞牛（TRIM_APPDEST 非空）与 faststrm 等第三方应用一致：manifest 声明 service_port=6010，
	// 应用监听端口，由飞牛网关反向代理，不使用 Unix Socket。
	// Windows/Linux 独立运行默认 6010，由一次性本地令牌保护。
	// Docker / 反向代理部署用 DYNV6_LISTEN（如 0.0.0.0:6010）或 DYNV6_DOCKER=1 开启服务模式，
	// 此时不启用本地令牌，必须使用管理员账号登录。
	listen := strings.TrimSpace(os.Getenv("DYNV6_LISTEN"))
	if listen == "" && strings.EqualFold(strings.TrimSpace(os.Getenv("DYNV6_DOCKER")), "1") {
		listen = "0.0.0.0:6010"
	}
	if listen == "" && os.Getenv("TRIM_APPDEST") != "" {
		listen = "0.0.0.0:6010"
	}
	devPort := strings.TrimSpace(os.Getenv("DYNV6_DEV_PORT"))
	if devPort == "" && listen == "" {
		devPort = "6010"
	}
	if listen != "" {
		// 服务模式优先：避免同时设置 DYNV6_DEV_PORT 时误启用本地令牌
		devPort = ""
	}
	return Paths{
		Dest:       dest,
		Etc:        etc,
		Var:        varDir,
		Share:      share,
		Shares:     shares,
		Accessible: accessible,
		Config:     filepath.Join(etc, "config.json"),
		State:      filepath.Join(varDir, "state.json"),
		AuthFile:   filepath.Join(varDir, "admin.json"),
		Socket:     envOr("DYNV6_SOCKET", filepath.Join(dest, "dynv6.sock")),
		TokenFile:  filepath.Join(varDir, "local-token"),
		DevPort:    devPort,
		Listen:     listen,
	}
}

func socketMode() os.FileMode {
	raw := strings.TrimSpace(os.Getenv("DYNV6_SOCKET_MODE"))
	if raw == "" {
		return 0600
	}
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0600
	}
	return os.FileMode(v)
}

func (a *App) listen() (net.Listener, error) {
	if a.paths.Listen != "" {
		return net.Listen("tcp", a.paths.Listen)
	}
	if a.paths.DevPort != "" {
		return net.Listen("tcp", "127.0.0.1:"+a.paths.DevPort)
	}
	_ = os.Remove(a.paths.Socket)
	ln, err := net.Listen("unix", a.paths.Socket)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(a.paths.Socket, socketMode())
	if err := applySocketGroup(a.paths.Socket); err != nil {
		a.log("设置 Socket 属组失败: %v", err)
	} else if g := strings.TrimSpace(os.Getenv("DYNV6_SOCKET_GROUP")); g != "" {
		a.log("Socket 属组已设置为 %s", g)
	}
	return newPeerListener(ln, a.log), nil
}

func demoEnabled() bool {
	return os.Getenv("DYNV6_DEMO") == "1"
}

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
}

const localTokenCookie = "dynv6_local"

func loadOrCreateLocalToken(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		if token := strings.TrimSpace(string(data)); len(token) >= 32 {
			return token, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	if err := atomicWrite(path, []byte(token+"\n"), 0600); err != nil {
		return token, err
	}
	return token, nil
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *App) localHostAllowed(r *http.Request) bool {
	if a.paths.DevPort == "" {
		return true
	}
	host := strings.ToLower(strings.TrimSpace(r.Host))
	port := a.paths.DevPort
	return host == "127.0.0.1:"+port || host == "localhost:"+port || host == "[::1]:"+port
}

func (a *App) localCookieValid(r *http.Request) bool {
	c, err := r.Cookie(localTokenCookie)
	if err != nil {
		return false
	}
	return secureEqual(c.Value, a.localToken)
}

func (a *App) localBearerValid(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	return secureEqual(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")), a.localToken)
}

func (a *App) setLocalCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     localTokenCookie,
		Value:    a.localToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// localRequestAllowed 在本地 TCP 模式下校验 Host 与一次性令牌；Unix Socket 模式不走这里。
func (a *App) localRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !a.localHostAllowed(r) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return false
	}
	if r.URL.Path == "/api/health" {
		return true
	}
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		if q := r.URL.Query().Get("token"); q != "" {
			if secureEqual(q, a.localToken) {
				a.setLocalCookie(w)
				target := r.URL.Path
				if target == "/index.html" {
					target = "/"
				}
				http.Redirect(w, r, target, http.StatusSeeOther)
				return false
			}
			http.Error(w, "invalid token", http.StatusForbidden)
			return false
		}
	}
	if a.localCookieValid(r) || a.localBearerValid(r) || a.sessionValid(r) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusForbidden, "本地访问令牌缺失或已失效，请从托盘重新打开界面")
	} else {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return false
}

// checkCSRF 拦截跨站 POST；前端 fetch 会带 X-Requested-With，命令行可用 Bearer。
func (a *App) checkCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := neturl.Parse(origin)
		if err != nil || u.Host == "" {
			return false
		}
		fwd := r.Header.Get("X-Forwarded-Host")
		if !strings.EqualFold(u.Host, r.Host) && (fwd == "" || !strings.EqualFold(u.Host, fwd)) {
			return false
		}
	}
	if r.Header.Get("X-Requested-With") != "dynv6" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	return true
}

func existingDynv6(port string) bool {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://127.0.0.1:" + port + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var h struct {
		OK  bool   `json:"ok"`
		App string `json:"app"`
	}
	if json.NewDecoder(resp.Body).Decode(&h) != nil {
		return false
	}
	return h.OK && h.App == "dynv6"
}

func main() {
	p := detectPaths()
	_ = os.MkdirAll(p.Etc, 0700)
	_ = os.MkdirAll(p.Var, 0700)
	demo := demoEnabled()
	a := newApp(p, demo)
	if p.DevPort != "" {
		if os.Getenv("DYNV6_DEV_INSECURE") == "1" {
			a.log("警告：DYNV6_DEV_INSECURE=1，本地端口不校验访问令牌；仅用于受信任的本机调试")
		} else {
			token, err := loadOrCreateLocalToken(p.TokenFile)
			if err != nil {
				a.log("本地访问令牌读写失败，本次使用临时令牌: %v", err)
			}
			if token == "" {
				a.log("无法生成本地访问令牌，请检查数据目录权限后重试")
				os.Exit(1)
			}
			a.localAuth = true
			a.localToken = token
			a.log("本地访问令牌已启用（文件 %s）", p.TokenFile)
		}
	}
	if demo {
		if _, err := os.Stat(p.Config); os.IsNotExist(err) {
			if err := a.saveConfig(demoConfig()); err != nil {
				a.log("写入演示配置失败: %v", err)
			}
		}
		a.log("演示模式：只显示示例数据，不执行真实任务（DYNV6_DEMO=1）")
	}
	if err := a.loadConfig(); err != nil {
		a.log("配置读取失败: %v", err)
	}
	a.loadState()
	a.log("dynv6 %s 启动，配置=%s 数据=%s", Version, p.Config, p.Var)
	a.log("外部命令：sh=%v openssl=%v", a.tools.HasShell(), a.tools.HasOpenSSL())
	if hint := vpnInterfaceHint(); hint != "" {
		a.log("网络提示：检测到 %s；如果启用了 VPN/代理/出口节点，IP 探测可能得到出口 IP，而不是家庭宽带 IP", hint)
	}
	if !demo {
		a.startScheduler()
	}
	url := ""
	if p.DevPort != "" {
		url = "http://127.0.0.1:" + p.DevPort + "/"
		if a.localAuth {
			url += "?token=" + neturl.QueryEscape(a.localToken)
		}
	}

	ln, err := a.listen()
	if err != nil {
		if runtime.GOOS == "windows" && p.DevPort != "" {
			if existingDynv6(p.DevPort) {
				a.log("端口 %s 已被已有实例占用，打开已有实例", p.DevPort)
				openBrowser(url)
				return
			}
			a.log("端口 %s 被其他程序占用，请设置 DYNV6_DEV_PORT 或关闭占用程序", p.DevPort)
			os.Exit(1)
		}
		a.log("监听失败: %v", err)
		os.Exit(1)
	}
	if p.Listen != "" {
		if os.Getenv("TRIM_APPDEST") != "" {
			a.log("飞牛模式：监听 %s（固定端口 6010，由飞牛网关反向代理）", p.Listen)
		} else {
			a.log("服务模式：监听 %s（Docker / 反向代理），请通过该地址访问并创建或登录管理员账号", p.Listen)
		}
	} else if p.DevPort == "" {
		a.log("Socket 权限=%04o；如网关不是 root，请设置 DYNV6_SOCKET_MODE=660 和 DYNV6_SOCKET_GROUP=网关组", socketMode())
	}
	a.log("服务已就绪（%s）", ln.Addr().String())
	if url != "" {
		a.log("本地访问地址：%s", url)
	}
	if runtime.GOOS == "windows" && url != "" && os.Getenv("DYNV6_NO_BROWSER") == "" {
		go openBrowser(url)
	}
	srv := &http.Server{
		Handler:           a.handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.log("收到退出信号，正在停止服务")
		_ = srv.Shutdown(shutdownCtx)
		a.cancelCurrent()
	}()
	if runtime.GOOS == "windows" && url != "" {
		go func() {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				a.log("服务退出: %v", err)
			}
		}()
		runTray(
			func() { openBrowser(url) },
			func() { _ = exec.Command("explorer", p.Var).Start() },
			func() {
				a.cancelCurrent()
				_ = srv.Close()
			},
			func() { a.log("任务栏托盘图标已加载") },
		)
		return
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		a.log("服务退出: %v", err)
		os.Exit(1)
	}
	a.log("服务已停止")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func (a *App) isAdminQuiet(r *http.Request) bool {
	// 本地管理员会话、网关注入的管理员身份，或显式关闭鉴权且处于本地开发端口
	if a.sessionValid(r) || a.gatewayAdmin(r) {
		return true
	}
	return a.authDisabled && (a.paths.DevPort != "" || a.paths.Listen != "")
}

func (a *App) isAdmin(r *http.Request) bool {
	if a.isAdminQuiet(r) {
		return true
	}
	a.log("拒绝访问 %s：缺少网关注入的身份头 X-Trim-Username 或非管理员", r.URL.Path)
	return false
}

// publicAPI 在服务模式下允许匿名访问：健康检查、鉴权状态与首次初始化/登录。
func publicAPI(path string) bool {
	switch path {
	case "/api/health", "/api/auth/status", "/api/setup/status", "/api/setup/admin", "/api/auth/login":
		return true
	}
	return false
}

func (a *App) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if a.localAuth && !a.localRequestAllowed(w, r) {
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/app/dynv6") {
			path = strings.TrimPrefix(path, "/app/dynv6")
		}
		if path == "" {
			path = "/"
		}
		// 服务模式（Docker / 反向代理）没有本地令牌：除健康检查与登录/初始化相关接口外，
		// 其余 API 一律要求管理员会话，避免匿名读取配置或触发任务。
		if a.paths.Listen != "" && !a.authDisabled && strings.HasPrefix(path, "/api/") && !publicAPI(path) {
			if a.gatewayUser(r) == "" && !a.sessionValid(r) {
				writeErr(w, http.StatusUnauthorized, "请先登录管理员账号")
				return
			}
		}

		switch {
		case path == "/" || path == "/index.html":
			a.serveStatic(w, "index.html")
		case path == "/static/app.js":
			a.serveStatic(w, "app.js")
		case path == "/static/style.css":
			a.serveStatic(w, "style.css")
		case strings.HasPrefix(path, "/static/images/"):
			a.serveImage(w, strings.TrimPrefix(path, "/static/images/"))
		case path == "/api/health":
			writeJSON(w, map[string]any{"ok": true, "app": "dynv6", "version": Version})
		case path == "/api/auth/status":
			a.handleAuthStatus(w, r)
		case path == "/api/setup/status":
			a.handleSetupStatus(w, r)
		case path == "/api/setup/admin":
			a.handleSetupAdmin(w, r)
		case path == "/api/auth/login":
			a.handleLogin(w, r)
		case path == "/api/auth/logout":
			a.handleLogout(w, r)
		case path == "/api/auth/change-password":
			a.handleChangePassword(w, r)
		case path == "/api/status":
			if a.demo {
				writeJSON(w, demoStatus())
				return
			}
			a.handleStatus(w, r)
		case path == "/api/config":
			a.handleConfig(w, r)
		case path == "/api/dirs":
			if a.demo {
				writeJSON(w, demoDirs())
				return
			}
			a.handleDirs(w, r)
		case path == "/api/probe":
			a.handleProbe(w, r)
		case path == "/api/logs":
			if a.demo {
				writeJSON(w, demoLogs())
				return
			}
			a.handleLogs(w, r)
		case path == "/api/files":
			if a.demo {
				writeJSON(w, demoFiles())
				return
			}
			a.handleFiles(w, r)
		case path == "/api/files/get":
			if a.demo {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte("演示文件：本地测试模式下不提供真实证书\n"))
				return
			}
			a.handleFileGet(w, r)
		case path == "/api/tasks":
			if a.demo {
				writeJSON(w, map[string]any{"ok": true, "tasks": demoTasks()})
				return
			}
			if !a.isAdmin(r) {
				writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
				return
			}
			writeJSON(w, map[string]any{"ok": true, "tasks": a.getTasks()})
		case strings.HasPrefix(path, "/api/actions/"):
			if a.demo {
				writeJSON(w, map[string]any{"ok": true, "task": Task{
					ID: "demo", Name: "演示", Status: "ok", StartedAt: nowISO(),
					Message: "本地测试模式不执行真实任务",
				}})
				return
			}
			a.handleAction(w, r, strings.TrimPrefix(path, "/api/actions/"))
		default:
			http.NotFound(w, r)
		}
	})
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	c := a.getConfig()
	auth := a.authStatus(r)
	admin := a.isAdminQuiet(r)
	if !admin {
		// 非管理员只给概览级信息，不暴露路径、任务、错误详情
		authRequired := ""
		if auth.SetupRequired {
			authRequired = "setup"
		} else if !auth.Authenticated {
			authRequired = "login"
		}
		writeJSON(w, map[string]any{
			"ok":            true,
			"version":       Version,
			"demo":          a.demo,
			"admin":         false,
			"auth_required": authRequired,
			"gateway":       auth.Gateway,
			"username":      auth.Username,
			"configured":    c.Domain != "" && c.Token != "",
			"env":           runtimeEnv(),
			"capabilities":  a.capabilities(),
			"network_hint":  vpnInterfaceHint(),
			"domain":        c.Domain,
		})
		return
	}
	authPaths := a.paths.Accessible
	if authPaths == nil {
		authPaths = []string{}
	}
	writeJSON(w, map[string]any{
		"ok":               true,
		"version":          Version,
		"demo":             a.demo,
		"admin":            true,
		"gateway":          auth.Gateway,
		"username":         auth.Username,
		"auth_disabled":    auth.AuthDisabled,
		"configured":       c.Domain != "" && c.Token != "",
		"env":              runtimeEnv(),
		"capabilities":     a.capabilities(),
		"network_hint":     vpnInterfaceHint(),
		"domain":           c.Domain,
		"paths_check":      a.pathChecks(c),
		"authorized_paths": authPaths,
		"state":            a.getState(),
		"tasks":            a.getTasks(),
		"busy":             a.isBusy(),
		"current":          a.currentTask(),
		"stage":            a.currentStage(),
		"paths": map[string]string{
			"output":    a.outDir(c),
			"backup":    a.backupDir(c),
			"acme_home": a.acmeHome(c),
			"config":    a.paths.Config,
		},
		"options": map[string]any{
			"auto_ddns":         c.AutoDDNS,
			"auto_renew":        c.AutoRenew,
			"auto_issue":        c.AutoIssue,
			"renew_days":        c.RenewDays,
			"ca":                c.CA,
			"allow_test_deploy": c.AllowTestDeploy,
		},
	})
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.isAdmin(r) {
			writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
			return
		}
		writeJSON(w, map[string]any{"ok": true, "config": publicConfig(a.getConfig())})
	case http.MethodPost:
		if !a.isAdmin(r) {
			writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
			return
		}
		if !a.checkCSRF(r) {
			writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
			return
		}
		var c Config
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
			writeErr(w, http.StatusBadRequest, "配置格式错误: "+err.Error())
			return
		}
		before := a.getConfig()
		if err := a.saveConfig(c); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		after := a.getConfig()
		if before.Domain != "" && before.Domain != after.Domain {
			a.log("域名已从 %s 变更为 %s：现有证书仍属于旧域名，请重新签发证书", before.Domain, after.Domain)
		}
		if before.Domain != after.Domain || before.CA != after.CA || before.KeyLength != after.KeyLength || before.Wildcard != after.Wildcard {
			// 让调度器尽快重新检查并按新配置签发，而不是等到证书到期
			a.setState(func(s *State) { s.LastCertCheck = "" })
		}
		a.log("配置已更新 domain=%s output=%s ca=%s", after.Domain, a.outDir(after), after.CA)
		if after.CA == "letsencrypt_test" {
			a.log("当前为 Let's Encrypt 测试环境：测试证书默认只导出，不会分发到 Emby/Plex（除非显式允许测试证书分发）")
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	n := 200
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 {
			n = x
		}
	}
	if n > 500 {
		n = 500
	}
	writeJSON(w, map[string]any{"ok": true, "lines": a.getLogs(n)})
}

func (a *App) handleFiles(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	c := a.getConfig()
	dir := a.outDir(c)
	entries, err := os.ReadDir(dir)
	type item struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"mod_time"`
	}
	list := make([]item, 0)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			list = append(list, item{e.Name(), info.Size(), info.ModTime().Format("2006-01-02 15:04:05")})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	writeJSON(w, map[string]any{"ok": true, "dir": dir, "files": list})
}

func (a *App) handleFileGet(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	name := r.URL.Query().Get("name")
	if !safeFileName(name) {
		writeErr(w, http.StatusBadRequest, "文件名不合法")
		return
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pfx", ".p12", ".pem", ".crt", ".key":
	default:
		writeErr(w, http.StatusBadRequest, "只允许下载证书与私钥文件")
		return
	}
	c := a.getConfig()
	dir := filepath.Clean(a.outDir(c))
	full := filepath.Join(dir, name)
	if filepath.Dir(full) != dir {
		writeErr(w, http.StatusBadRequest, "路径越界")
		return
	}
	if info, err := os.Lstat(full); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		writeErr(w, http.StatusNotFound, "文件不存在")
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// 文件名里若带引号/反斜杠会破坏头部，这里做转义并同时给出 UTF-8 形式
	safe := strings.NewReplacer("\"", "_", "\\", "_", "\r", "_", "\n", "_").Replace(name)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safe+"\"; filename*=UTF-8''"+neturl.PathEscape(name))
	_, _ = w.Write(data)
}

func (a *App) handleAction(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	if !a.checkCSRF(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败，请刷新页面后重试")
		return
	}
	var fn func(Config) error
	if name == "cancel" {
		writeJSON(w, map[string]any{"ok": true, "canceled": a.cancelCurrent()})
		return
	}
	switch name {
	case "ddns":
		fn = func(c Config) error { return a.runDDNS(true) }
	case "issue":
		fn = func(c Config) error { return a.issueAndDeploy(c, true) }
	case "renew":
		fn = func(c Config) error { return a.renewAndDeploy(c, true) }
	case "check":
		fn = a.checkCert
	case "convert":
		fn = a.convertAndDeploy
	case "deploy":
		fn = a.deploy
	case "test-tg":
		fn = a.testTelegram
	default:
		writeErr(w, http.StatusNotFound, "未知操作")
		return
	}
	lane := "cert"
	if name == "ddns" {
		lane = "ddns"
	} else if name == "test-tg" {
		lane = "notify"
	}
	t, ok := a.startTask(name, lane, fn)
	if !ok {
		writeErr(w, http.StatusConflict, t.Message)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "task": t})
}
