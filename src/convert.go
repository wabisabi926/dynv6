package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (a *App) convertAll(c Config) error {
	a.setStage("转换 PFX/P12")
	a.setState(func(s *State) { s.LastDeployAttempt = nowISO() })
	f := a.fileSet(c)
	for _, k := range []string{"key", "fullchain"} {
		if _, err := os.Stat(f[k]); err != nil {
			return fmt.Errorf("缺少源文件 %s，请先签发或续期证书", f[k])
		}
	}
	mode := parseMode(c.FileMode)
	if err := a.makePKCS12(c, f["key"], f["fullchain"], f["pfx"], c.PFXPassword, mode); err != nil {
		return err
	}
	if err := a.makePKCS12(c, f["key"], f["fullchain"], f["p12"], c.P12Password, mode); err != nil {
		return err
	}
	a.log("证书格式转换完成：PFX（Emby）与 P12（Plex）已生成于 %s", a.outDir(c))
	return nil
}

// makePKCS12 使用 Plex 新版要求的加密参数生成 PKCS#12，密码经临时文件传递，不出现在命令行
func (a *App) makePKCS12(c Config, key, chain, out, password string, mode os.FileMode) error {
	if !a.tools.HasOpenSSL() {
		return fmt.Errorf("找不到 openssl，无法生成 %s；Windows 请安装 Git for Windows（自带 openssl）；DDNS 与分发不受影响", filepath.Base(out))
	}
	tmp := out + fmt.Sprintf(".tmp-%d", os.Getpid())
	defer os.Remove(tmp)

	passArg := "pass:"
	if password != "" {
		passFile := filepath.Join(a.paths.Var, fmt.Sprintf(".pass-%d", os.Getpid()))
		if err := os.WriteFile(passFile, []byte(password+"\n"), 0600); err != nil {
			return err
		}
		defer os.Remove(passFile)
		passArg = "file:" + passFile
	}

	args := []string{
		"pkcs12", "-export",
		"-out", tmp,
		"-inkey", key,
		"-in", chain,
		"-name", "dynv6-" + c.Domain,
		"-passout", passArg,
		"-certpbe", "AES-256-CBC",
		"-keypbe", "AES-256-CBC",
		"-macalg", "SHA256",
	}
	if _, err := a.runCmd(a.tools.OpenSSL, args, nil, 3*time.Minute, a.secrets(c), a.log); err != nil {
		return fmt.Errorf("生成 %s 失败（需要 OpenSSL 1.1.1 及以上）: %w", filepath.Base(out), err)
	}

	verify := []string{"pkcs12", "-in", tmp, "-nokeys", "-passin", passArg, "-info", "-noout"}
	if _, err := a.runCmd(a.tools.OpenSSL, verify, nil, 30*time.Second, a.secrets(c), nil); err != nil {
		a.log("警告：%s 自检未通过，请确认 openssl 版本与证书链完整性", filepath.Base(out))
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	return atomicWrite(out, data, mode)
}
