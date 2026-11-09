package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Tools 记录当前系统可用的外部命令。Windows 上 Git for Windows 自带 sh/openssl，
// 找到后把它的 bin/usr\bin 加进子进程 PATH，acme.sh 内部的 curl 也能正常调用。
type Tools struct {
	Sh      string
	OpenSSL string
	Dirs    []string
}

func (t Tools) HasShell() bool   { return t.Sh != "" }
func (t Tools) HasOpenSSL() bool { return t.OpenSSL != "" }

func toolName(p string) string {
	if p == "" {
		return "未找到"
	}
	return p
}

func resolveTools() Tools {
	t := Tools{Sh: resolveTool("sh", os.Getenv("DYNV6_SH"), shellCandidates()), OpenSSL: resolveTool("openssl", os.Getenv("DYNV6_OPENSSL"), opensslCandidates())}
	if runtime.GOOS == "windows" {
		for _, dir := range windowsToolDirs() {
			if t.Sh == "" {
				if p := filepath.Join(dir, "sh.exe"); fileExists(p) {
					t.Sh = p
				}
			}
			if t.OpenSSL == "" {
				if p := filepath.Join(dir, "openssl.exe"); fileExists(p) {
					t.OpenSSL = p
				}
			}
		}
	}
	for _, p := range []string{t.Sh, t.OpenSSL} {
		if p != "" {
			t.Dirs = append(t.Dirs, filepath.Dir(p))
		}
	}
	if runtime.GOOS == "windows" {
		for _, dir := range windowsToolDirs() {
			if fileExists(filepath.Join(dir, "curl.exe")) {
				t.Dirs = append(t.Dirs, dir)
			}
		}
	}
	t.Dirs = dedupePaths(t.Dirs)
	return t
}

func lookPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// resolveTool 依次尝试：显式环境变量 → PATH → 常见绝对路径。
// 飞牛等环境可能只给 Go 进程极简 PATH，绝对路径兜底可以避免“找不到 sh”。
func resolveTool(name, override string, candidates []string) string {
	if p := strings.TrimSpace(override); p != "" {
		if fileExists(p) {
			return p
		}
	}
	if p := lookPath(name); p != "" {
		return p
	}
	for _, p := range candidates {
		if isExecutableFile(p) {
			return p
		}
	}
	return ""
}

func shellCandidates() []string {
	return []string{"/bin/sh", "/usr/bin/sh", "/usr/local/bin/sh", "/sbin/sh", "/bin/bash", "/usr/bin/bash"}
}

func opensslCandidates() []string {
	return []string{"/usr/bin/openssl", "/usr/local/bin/openssl", "/bin/openssl", "/usr/local/ssl/bin/openssl", "/opt/homebrew/bin/openssl"}
}

func isExecutableFile(p string) bool {
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return st.Mode()&0111 != 0
}

func windowsToolDirs() []string {
	var roots []string
	for _, key := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if v := os.Getenv(key); v != "" {
			roots = append(roots, v)
		}
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		roots = append(roots, filepath.Join(v, "Programs"))
	}
	var dirs []string
	for _, root := range roots {
		for _, sub := range []string{
			filepath.Join("Git", "bin"),
			filepath.Join("Git", "usr", "bin"),
			filepath.Join("Git", "mingw64", "bin"),
		} {
			dirs = append(dirs, filepath.Join(root, sub))
		}
	}
	return dirs
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dedupePaths(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		out = append(out, p)
	}
	return out
}

func (a *App) capabilities() map[string]bool {
	return map[string]bool{
		"ddns":    true,
		"issue":   true,
		"convert": true,
	}
}

// childEnv 在 Windows 上把 Git for Windows 的 bin/usr\bin 放到 PATH 前面
func (a *App) childEnv(extra []string) []string {
	env := os.Environ()
	if len(a.tools.Dirs) > 0 {
		cur := ""
		filtered := make([]string, 0, len(env)+1)
		for _, kv := range env {
			if strings.HasPrefix(strings.ToUpper(kv), "PATH=") {
				cur = kv[5:]
				continue
			}
			filtered = append(filtered, kv)
		}
		sep := string(os.PathListSeparator)
		env = append(filtered, "PATH="+strings.Join(a.tools.Dirs, sep)+sep+cur)
	}
	return append(env, extra...)
}
