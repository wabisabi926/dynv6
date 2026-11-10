package main

import (
	"fmt"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
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
	// PFX/P12 内含私钥，主输出固定 0600；分发到目标目录时由 deploy 单独放宽到 0644
	mode := os.FileMode(0600)
	if err := a.makePKCS12(c, f["key"], f["fullchain"], f["pfx"], c.PFXPassword, mode); err != nil {
		return err
	}
	if err := a.makePKCS12(c, f["key"], f["fullchain"], f["p12"], c.P12Password, mode); err != nil {
		return err
	}
	a.log("证书格式转换完成：PFX（Emby）与 P12（Plex）已生成于 %s", a.outDir(c))
	return nil
}

// makePKCS12 使用纯 Go 实现生成 PKCS#12，不再依赖 openssl。
func (a *App) makePKCS12(c Config, keyPath, chainPath, out, password string, mode os.FileMode) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	signer, err := parsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("读取私钥失败: %w", err)
	}
	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		return err
	}
	leaf, certs, err := parseCertificates(chainData)
	if err != nil {
		return err
	}
	caCerts := certs[1:]
	data, err := pkcs12.Modern.Encode(signer, leaf, caCerts, password)
	if err != nil {
		return fmt.Errorf("生成 %s 失败: %w", out, err)
	}
	return atomicWrite(out, data, mode)
}
