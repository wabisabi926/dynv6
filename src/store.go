package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type State struct {
	LastIPv4          string `json:"last_ipv4"`
	LastIPv6          string `json:"last_ipv6"`
	LastDDNSDomain    string `json:"last_ddns_domain"`
	LastDDNSTokenHash string `json:"last_ddns_token_hash"`
	LastDDNSAt        string `json:"last_ddns_at"`
	LastDDNSAttempt   string `json:"last_ddns_attempt"`
	LastDDNSResult    string `json:"last_ddns_result"`
	LastCertCheck     string `json:"last_cert_check"`
	LastIssueAt       string `json:"last_issue_at"`
	LastRenewAt       string `json:"last_renew_at"`
	LastDeployAt      string `json:"last_deploy_at"`
	LastDeployAttempt string `json:"last_deploy_attempt"`
	CertCA            string `json:"cert_ca"`
	CertNotAfter      string `json:"cert_not_after"`
	CertDaysLeft      int    `json:"cert_days_left"`
	LastError         string `json:"last_error"`
}

type Task struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Stage     string `json:"stage"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	Message   string `json:"message"`
}

type App struct {
	paths        Paths
	demo         bool
	cfgMu        sync.RWMutex
	cfg          Config
	stateMu      sync.RWMutex
	state        State
	stateWriteMu sync.Mutex
	localAuth    bool
	localToken   string
	authMu       sync.Mutex
	admin        AdminAuth
	sessions     map[string]adminSession
	loginGuard   map[string]loginAttempt
	authDisabled bool
	authBroken   bool // admin.json 存在但损坏/不可读：禁止重新初始化（fail-closed）
	logMu        sync.Mutex
	logs         []string
	logFile      *os.File
	logBytes     int64
	taskMu       sync.Mutex
	tasks        []Task
	busy         bool
	current      string
	laneBusy     map[string]bool
	cmdMu        sync.Mutex
	cancelReq    bool
	notifyMu     sync.Mutex
	lastNotify   map[string]time.Time
	pathMu       sync.Mutex
	pathCheck    map[string]bool
	pathCheckAt  time.Time
}

func newApp(p Paths, demo bool) *App {
	a := &App{
		paths:      p,
		demo:       demo,
		logs:       make([]string, 0, 600),
		tasks:      make([]Task, 0, 100),
		laneBusy:   map[string]bool{},
		lastNotify: map[string]time.Time{},
		sessions:   map[string]adminSession{},
		loginGuard: map[string]loginAttempt{},
	}
	a.authDisabled = os.Getenv("DYNV6_AUTH_DISABLED") == "1"
	if p.Var != "" {
		_ = os.MkdirAll(p.Var, 0700)
		logPath := filepath.Join(p.Var, "dynv6.log")
		if st, err := os.Stat(logPath); err == nil && st.Size() > 5<<20 {
			_ = os.Remove(logPath + ".1")
			_ = os.Rename(logPath, logPath+".1")
		}
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			a.logFile = f
			if st, err := f.Stat(); err == nil {
				a.logBytes = st.Size()
			}
		}
	}
	a.loadAdminAuth()
	if a.authDisabled {
		a.log("警告：DYNV6_AUTH_DISABLED=1，本地管理员账号鉴权已禁用")
	}
	return a
}

// log 同时写日志文件、标准输出和内存环形缓冲；日志文件由应用自身轮转
func (a *App) log(format string, v ...any) {
	line := fmt.Sprintf("[%s] %s", nowISO(), fmt.Sprintf(format, v...))
	fmt.Println(line)
	a.logMu.Lock()
	a.logs = append(a.logs, line)
	if a.logFile != nil {
		n, _ := a.logFile.WriteString(line + "\n")
		a.logBytes += int64(n)
		// 长期运行时日志会一直长，超过 10MB 自动轮转一份
		if a.logBytes > 10<<20 {
			a.rotateLogLocked()
		}
	}
	if len(a.logs) > 500 {
		a.logs = append([]string(nil), a.logs[len(a.logs)-500:]...)
	}
	a.logMu.Unlock()
}

// rotateLogLocked 关闭当前日志并重命名为 .1，然后重新打开；调用方需持有 logMu
func (a *App) rotateLogLocked() {
	if a.logFile == nil {
		return
	}
	path := a.logFile.Name()
	_ = a.logFile.Close()
	a.logFile = nil
	_ = os.Remove(path + ".1")
	_ = os.Rename(path, path+".1")
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		a.logFile = f
	}
	a.logBytes = 0
}

func (a *App) getLogs(n int) []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if n <= 0 || n > len(a.logs) {
		n = len(a.logs)
	}
	out := make([]string, n)
	copy(out, a.logs[len(a.logs)-n:])
	return out
}

func (a *App) loadState() {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	data, err := os.ReadFile(a.paths.State)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &a.state)
}

func (a *App) saveState() {
	a.stateWriteMu.Lock()
	defer a.stateWriteMu.Unlock()
	a.stateMu.RLock()
	data, _ := json.MarshalIndent(a.state, "", "  ")
	a.stateMu.RUnlock()
	if err := atomicWrite(a.paths.State, data, 0600); err != nil {
		a.log("保存状态失败: %v", err)
	}
}

func (a *App) getState() State {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.state
}

func (a *App) setState(fn func(*State)) {
	a.stateMu.Lock()
	func() {
		defer a.stateMu.Unlock()
		fn(&a.state)
	}()
	a.saveState()
}

func (a *App) getTasks() []Task {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	out := make([]Task, len(a.tasks))
	copy(out, a.tasks)
	return out
}

func (a *App) isBusy() bool {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	return a.busy
}

func (a *App) currentTask() string {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	return a.current
}

// laneBusyNow 判断某个 lane 是否忙；调度器用它替代全局 busy，避免证书任务饿死 DDNS
func (a *App) laneBusyNow(lane string) bool {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	return a.laneBusy[lane]
}

func (a *App) currentStage() string {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	for _, t := range a.tasks {
		if t.Status == "running" && t.Name == a.current {
			return t.Stage
		}
	}
	for _, t := range a.tasks {
		if t.Status == "running" {
			return t.Stage
		}
	}
	return ""
}

// setStage 更新证书类任务的当前阶段；DDNS 进度看实时日志
func (a *App) setStage(stage string) {
	a.taskMu.Lock()
	defer a.taskMu.Unlock()
	for i := range a.tasks {
		if a.tasks[i].Status != "running" {
			continue
		}
		switch a.tasks[i].Name {
		case "issue", "renew", "cert-check", "convert", "deploy", "deploy-retry", "check":
			a.tasks[i].Stage = stage
		}
	}
}

func (a *App) wasCanceled() bool {
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()
	return a.cancelReq
}

// cancelCurrent 标记取消；证书签发为内置 HTTP 流程，会在阶段间尽快退出
func (a *App) cancelCurrent() bool {
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()
	a.cancelReq = true
	return true
}

// capabilities 列出当前版本支持的功能（证书签发与转换均为内置实现）
func (a *App) capabilities() map[string]bool {
	return map[string]bool{
		"ddns":    true,
		"issue":   true,
		"convert": true,
	}
}

// startTask 按 lane 串行：DDNS 与证书任务互不阻塞
func (a *App) startTask(name, lane string, fn func(Config) error) (Task, bool) {
	lane = strings.TrimSpace(lane)
	if lane == "" {
		lane = "default"
	}
	a.taskMu.Lock()
	if a.laneBusy[lane] {
		cur := ""
		for _, t := range a.tasks {
			if t.Status == "running" {
				cur = t.Name
				break
			}
		}
		a.taskMu.Unlock()
		return Task{Status: "busy", Message: "该任务正在运行: " + cur}, false
	}
	t := Task{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Name:      name,
		Status:    "running",
		Stage:     "准备",
		StartedAt: nowISO(),
	}
	a.laneBusy[lane] = true
	a.busy = true
	a.current = name
	a.tasks = append([]Task{t}, a.tasks...)
	if len(a.tasks) > 50 {
		a.tasks = a.tasks[:50]
	}
	a.taskMu.Unlock()
	a.cmdMu.Lock()
	a.cancelReq = false
	a.cmdMu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("任务内部错误: %v", r)
				a.log("任务 %s panic: %s\n%s", name, msg, debug.Stack())
				a.setState(func(s *State) { s.LastError = msg })
				a.finishTask(t, lane, "error", msg)
			}
		}()
		c := a.getConfig()
		secrets := a.secrets(c)
		err := fn(c)
		msg := "完成"
		status := "ok"
		if err != nil {
			msg = maskSecrets(err.Error(), secrets)
			status = "error"
			a.setState(func(s *State) { s.LastError = msg })
			a.log("任务 %s 失败: %s", name, msg)
			if name == "ddns" {
				a.setState(func(s *State) {
					s.LastDDNSAttempt = nowISO()
					s.LastDDNSResult = "失败：" + msg
				})
			}
			switch name {
			case "ddns":
				a.notify("DDNS 更新失败", msg)
			case "deploy", "deploy-retry":
				a.notify("分发失败", msg)
			case "convert":
				a.notify("格式转换失败", msg)
			case "cert-check":
				a.notify("证书检查失败", msg)
			}
		} else {
			a.setState(func(s *State) { s.LastError = "" })
			a.log("任务 %s 完成", name)
		}
		a.finishTask(t, lane, status, msg)
	}()
	return t, true
}

// finishTask 统一更新任务结果并释放 lane，正常结束与 panic recovery 共用。
func (a *App) finishTask(t Task, lane, status, msg string) {
	a.taskMu.Lock()
	for i := range a.tasks {
		if a.tasks[i].ID == t.ID {
			a.tasks[i].Status = status
			a.tasks[i].Message = msg
			a.tasks[i].Stage = ""
			a.tasks[i].EndedAt = nowISO()
		}
	}
	delete(a.laneBusy, lane)
	a.busy = false
	a.current = ""
	for _, x := range a.tasks {
		if x.Status == "running" {
			a.busy = true
			a.current = x.Name
			break
		}
	}
	a.taskMu.Unlock()
	a.cmdMu.Lock()
	a.cancelReq = false
	a.cmdMu.Unlock()
}
