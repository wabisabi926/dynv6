package main

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed web/index.html web/app.js web/style.css web/images/ICON_64.PNG
var webFiles embed.FS

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// serveStatic 优先读取磁盘上的 ui/www 文件，方便直接改页面而无需重新编译
func (a *App) serveStatic(w http.ResponseWriter, name string) {
	var data []byte
	disk := filepath.Join(a.paths.Dest, "ui", "www", name)
	if b, err := os.ReadFile(disk); err == nil {
		data = b
	} else {
		b, err := webFiles.ReadFile("web/" + name)
		if err != nil {
			http.Error(w, "页面资源缺失", http.StatusNotFound)
			return
		}
		data = b
	}
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// serveImage 只提供 ui/images 下的 PNG 图标，文件名做白名单校验
func (a *App) serveImage(w http.ResponseWriter, name string) {
	if !safeFileName(name) || !strings.HasSuffix(strings.ToUpper(name), ".PNG") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(a.paths.Dest, "ui", "images", name))
	if err != nil {
		// Windows 本地测试版没有安装目录，回退到内嵌图标
		if name == "ICON_64.PNG" {
			data, err = webFiles.ReadFile("web/images/ICON_64.PNG")
		}
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}
