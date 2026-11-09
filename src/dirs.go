package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DirRoot struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type DirEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// dirRoots 返回允许浏览的根目录：应用自己的目录、声明的共享目录、用户在应用设置里授权的路径，
// 以及当前配置使用的目录。不会把整盘作为根，避免越权浏览。
func (a *App) dirRoots(c Config) []DirRoot {
	seen := map[string]bool{}
	out := make([]DirRoot, 0, 10)
	add := func(name, raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		p := expand(raw, &c, &a.paths)
		if !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		if seen[p] {
			return
		}
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, DirRoot{Name: name, Path: p})
	}
	add("应用数据", a.paths.Var)
	add("应用配置", a.paths.Etc)
	add("应用目录", a.paths.Dest)
	add("证书共享目录", a.paths.Share)
	for _, s := range a.paths.Shares {
		add("共享目录", s)
	}
	for _, s := range a.paths.Accessible {
		add("已授权路径", s)
	}
	add("输出目录", c.OutputDir)
	add("备份目录", c.BackupDir)
	add("acme 目录", c.AcmeHome)
	if p := safeParent(a.outDir(c)); p != "" {
		add("输出目录上级", p)
	}
	if runtimeEnv() == "fnOS" {
		for _, v := range []string{"/vol1", "/vol2", "/vol3", "/vol4", "/vol5", "/vol6", "/vol7", "/vol8", "/vol9"} {
			add("存储空间 "+v+"（只读浏览，写入需授权）", v)
		}
	}
	return out
}

func safeParent(p string) string {
	if p == "" {
		return ""
	}
	d := filepath.Dir(p)
	if d == p || d == string(os.PathSeparator) {
		return ""
	}
	if len(d) == 3 && d[1] == ':' {
		return ""
	}
	return d
}

func underAnyRoot(p string, roots []DirRoot) bool {
	for _, r := range roots {
		if p == r.Path || strings.HasPrefix(p, r.Path+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// handleDirs 列出可浏览根或某个根下的子目录；仅管理员可调用
func (a *App) handleDirs(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(r) {
		writeErr(w, http.StatusForbidden, "需要飞牛管理员权限")
		return
	}
	c := a.getConfig()
	roots := a.dirRoots(c)
	resp := map[string]any{"ok": true, "roots": roots}

	p := strings.TrimSpace(r.URL.Query().Get("path"))
	if p == "" {
		writeJSON(w, resp)
		return
	}
	p = expand(p, &c, &a.paths)
	if !filepath.IsAbs(p) || hasDotDot(p) {
		resp["error"] = "路径不合法"
		writeJSON(w, resp)
		return
	}
	p = filepath.Clean(p)
	realPath, err := filepath.EvalSymlinks(p)
	if err != nil {
		resp["error"] = "目录不存在或不可访问：" + err.Error()
		writeJSON(w, resp)
		return
	}
	p = realPath
	resp["path"] = p
	if parent := filepath.Dir(p); underAnyRoot(parent, roots) {
		resp["parent"] = parent
	}
	if !underAnyRoot(p, roots) {
		resp["error"] = "该目录不在可访问范围内；如需其他位置，请先在飞牛「应用设置 → 授权路径」中授权"
		writeJSON(w, resp)
		return
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		resp["error"] = "读取目录失败：" + err.Error()
		writeJSON(w, resp)
		return
	}
	dirs := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		// 跳过符号链接，避免通过软链接浏览到授权范围之外
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		full := filepath.Join(p, e.Name())
		info, err := os.Stat(full)
		if err != nil || !info.IsDir() {
			continue
		}
		dirs = append(dirs, DirEntry{Name: e.Name(), Path: full})
	}
	sort.Slice(dirs, func(i, j int) bool {
		return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name)
	})
	if len(dirs) > 300 {
		dirs = dirs[:300]
	}
	resp["dirs"] = dirs
	writeJSON(w, resp)
}
