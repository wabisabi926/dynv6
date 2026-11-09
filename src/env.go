package main

import (
	"os"
	"runtime"
	"time"
)

// runtimeEnv 判断当前运行环境；路径默认值全部用变量表达，因此不需要按平台分支
func runtimeEnv() string {
	if os.Getenv("TRIM_APPNAME") != "" {
		return "fnOS"
	}
	if os.Getenv("DYNV6_DOCKER") != "" {
		return "docker"
	}
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "generic"
}

// pathWritable 检查目录是否可写，用于在界面上提示路径是否适配当前环境
func pathWritable(dir string) bool {
	if dir == "" {
		return false
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".dynv6-write-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_, writeErr := f.WriteString("ok")
	closeErr := f.Close()
	_ = os.Remove(name)
	return writeErr == nil && closeErr == nil
}

// pathChecks 缓存目录可写检测，避免 status 每 5 秒轮询都写一次盘
func (a *App) pathChecks(c Config) map[string]bool {
	a.pathMu.Lock()
	defer a.pathMu.Unlock()
	if a.pathCheck != nil && time.Since(a.pathCheckAt) < 30*time.Second {
		return a.pathCheck
	}
	m := map[string]bool{
		"output":    pathWritable(a.outDir(c)),
		"backup":    pathWritable(a.backupDir(c)),
		"acme_home": pathWritable(a.acmeHome(c)),
	}
	a.pathCheck = m
	a.pathCheckAt = time.Now()
	return m
}

func (a *App) invalidatePathChecks() {
	a.pathMu.Lock()
	a.pathCheck = nil
	a.pathMu.Unlock()
}
