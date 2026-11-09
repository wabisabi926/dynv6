package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// deploy 把主输出目录中的证书分发到用户自定义的目标路径（飞牛原生 Emby/Plex / 自定义目录）
func (a *App) deploy(c Config) error {
	a.setStage("分发到目标")
	a.setState(func(s *State) { s.LastDeployAttempt = nowISO() })
	if a.stagingDeployBlocked(c) {
		return fmt.Errorf("当前是测试环境证书且未允许测试证书分发；请切回正式机构，或在设置中显式允许")
	}
	st := a.getState()
	savedCA := readConfValue(a.certConfPath(c), "Le_API")
	if c.CA == "letsencrypt" && (st.CertCA == "letsencrypt_test" || savedCA == caServerLETest) {
		return fmt.Errorf("输出目录里仍是测试证书；请先重新签发正式证书再分发")
	}
	f := a.fileSet(c)
	defMode := parseMode(c.FileMode)
	var errs []string
	count := 0

	for _, t := range c.Targets {
		if !t.Enabled {
			continue
		}
		dir := expand(t.Dir, &c, &a.paths)
		if dir == "" {
			a.log("%s: 目标目录为空，已跳过", t.Name)
			continue
		}
		if !filepath.IsAbs(dir) || hasDotDot(dir) || strings.Contains(dir, "${") {
			errs = append(errs, fmt.Sprintf("%s: 目标目录必须是绝对路径且不能包含 .. 或未知变量（当前 %s）", t.Name, dir))
			continue
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			errs = append(errs, fmt.Sprintf("%s: 无法创建 %s (%v)", t.Name, dir, err))
			continue
		}
		if runtimeEnv() == "fnOS" {
			if real, err := filepath.EvalSymlinks(dir); err == nil && !a.pathAllowedOnFnOS(real, c) {
				errs = append(errs, fmt.Sprintf("%s: 目标目录通过符号链接指向未授权位置 %s", t.Name, real))
				continue
			}
		}
		name := expand(t.Filename, &c, &a.paths)
		if name == "" {
			name = a.prefix(c)
		}
		if !validTemplateName(name) || strings.Contains(name, "${") {
			errs = append(errs, t.Name+": 文件名不能包含路径分隔符、.. 或未知变量（当前 "+name+"）")
			continue
		}
		mode := parseModeFor(t.Mode, defMode)

		type pair struct {
			src, dst string
			mode     os.FileMode
		}
		var pairs []pair
		switch t.Kind {
		case "emby":
			if name == "" || !strings.Contains(name, ".") {
				name = a.prefix(c) + ".pfx"
			}
			pairs = []pair{{f["pfx"], filepath.Join(dir, name), mode}}
		case "plex":
			if name == "" || !strings.Contains(name, ".") {
				name = a.prefix(c) + ".p12"
			}
			pairs = []pair{{f["p12"], filepath.Join(dir, name), mode}}
		case "pem":
			pairs = []pair{
				{f["key"], filepath.Join(dir, name+".key"), 0600}, // PEM 私钥不能是世界可读
				{f["cert"], filepath.Join(dir, name+".crt"), mode},
				{f["fullchain"], filepath.Join(dir, name+".fullchain.crt"), mode},
				{f["chain"], filepath.Join(dir, name+".chain.crt"), mode},
			}
		default:
			errs = append(errs, t.Name+": 未知目标类型 "+t.Kind)
			continue
		}

		for _, p := range pairs {
			if sameFilePath(p.src, p.dst) {
				a.log("%s: 目标与主输出相同，跳过自复制 %s", t.Name, filepath.Base(p.dst))
				continue
			}
			if _, err := os.Stat(p.src); err != nil {
				errs = append(errs, fmt.Sprintf("%s: 源文件不存在 %s", t.Name, filepath.Base(p.src)))
				continue
			}
			if err := copyFile(p.src, p.dst, p.mode); err != nil {
				errs = append(errs, fmt.Sprintf("%s: 复制 %s 失败 (%v)", t.Name, filepath.Base(p.dst), err))
				continue
			}
			count++
		}
	}

	if len(errs) > 0 {
		// 清空“上次成功分发”时间，让调度器知道本次证书还没有完整分发
		a.setState(func(s *State) { s.LastDeployAt = "" })
		return fmt.Errorf("分发完成 %d 个文件，但存在问题：%s", count, strings.Join(errs, "；"))
	}
	a.setState(func(s *State) { s.LastDeployAt = nowISO() })
	a.log("分发完成，共 %d 个文件", count)
	return nil
}

// backupCurrent 在重新签发/续期前把现有证书备份一份
func (a *App) backupCurrent(c Config) {
	dir := a.backupDir(c)
	if dir == "" {
		return
	}
	stamp := time.Now().Format("20060102-150405")
	dst := filepath.Join(dir, stamp)
	f := a.fileSet(c)
	saved := 0
	for k, src := range f {
		if k == "pfx" || k == "p12" {
			continue
		}
		if data, err := os.ReadFile(src); err == nil {
			if err := atomicWrite(filepath.Join(dst, filepath.Base(src)), data, 0600); err == nil {
				saved++
			}
		}
	}
	if saved > 0 {
		a.log("已备份 %d 个旧证书文件到 %s", saved, dst)
		a.pruneBackups(dir, 10)
	}
}

// pruneBackups 只保留最近 keep 份备份，避免长期运行无限占用磁盘。
func (a *App) pruneBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for i, name := range names {
		if i < keep {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
}
