package main

import (
	"fmt"
	"os"
	"time"
)

func (a *App) refreshCertInfo(c Config) {
	f := a.fileSet(c)
	t, err := certNotAfter(f["fullchain"])
	if err != nil {
		a.log("读取证书有效期失败: %v", err)
		a.setState(func(s *State) {
			s.CertNotAfter = ""
			s.CertDaysLeft = 0
		})
		return
	}
	days := int(time.Until(t).Hours() / 24)
	a.setState(func(s *State) {
		s.CertNotAfter = t.Format("2006-01-02 15:04:05")
		s.CertDaysLeft = days
	})
	a.log("当前证书到期时间 %s，剩余 %d 天", t.Format("2006-01-02"), days)
}

// stagingDeployBlocked 判断是否应阻止把测试证书分发到目标。
func (a *App) stagingDeployBlocked(c Config) bool {
	return c.CA == "letsencrypt_test" && !c.AllowTestDeploy
}

// afterCertReady 统一处理“签发/续期成功”后的转换、自检、分发与通知。
func (a *App) afterCertReady(c Config, action string) error {
	a.setStage("转换 PFX/P12")
	if err := a.convertAll(c); err != nil {
		return fmt.Errorf("证书已%s，但格式转换失败：%w", action, err)
	}
	a.refreshCertInfo(c)
	if a.stagingDeployBlocked(c) {
		a.log("当前为测试环境证书，已跳过分发；如需覆盖 Emby/Plex，请到设置勾选「允许分发测试证书」")
		st := a.getState()
		a.notify("测试证书已签发（未分发）", fmt.Sprintf("域名：%s\n到期：%s\n剩余：%d 天\n如需分发请显式允许测试证书分发", c.Domain, st.CertNotAfter, st.CertDaysLeft))
		return nil
	}
	a.setStage("分发到目标")
	if err := a.deploy(c); err != nil {
		a.log("证书已%s，但分发失败: %v", action, err)
		a.notify("证书已"+action+"，但分发失败", err.Error())
		return fmt.Errorf("证书已%s，但分发失败：%w", action, err)
	}
	st := a.getState()
	title := "证书签发成功"
	if action == "续期" {
		title = "证书续期成功"
	}
	if c.CA == "letsencrypt_test" {
		title = "测试证书已签发并分发（仅供调试）"
	}
	a.notify(title, fmt.Sprintf("域名：%s\n到期：%s\n剩余：%d 天", c.Domain, st.CertNotAfter, st.CertDaysLeft))
	return nil
}

func (a *App) issueAndDeploy(c Config, force bool) error {
	a.setStage("备份当前证书")
	a.backupCurrent(c)
	a.setStage("签发证书")
	if err := a.issueCert(c, force); err != nil {
		return err
	}
	a.setState(func(s *State) {
		s.LastIssueAt = nowISO()
		s.CertCA = c.CA
	})
	return a.afterCertReady(c, "签发")
}

func (a *App) renewAndDeploy(c Config, force bool) error {
	a.setStage("备份当前证书")
	a.backupCurrent(c)
	a.setStage("续期证书")
	if err := a.renewCert(c, force); err != nil {
		return err
	}
	a.setState(func(s *State) {
		s.LastRenewAt = nowISO()
		s.CertCA = c.CA
	})
	return a.afterCertReady(c, "续期")
}

func (a *App) convertAndDeploy(c Config) error {
	a.setStage("转换 PFX/P12")
	if err := a.convertAll(c); err != nil {
		return err
	}
	a.refreshCertInfo(c)
	if a.stagingDeployBlocked(c) {
		a.log("当前为测试环境证书，已跳过分发；如需覆盖 Emby/Plex，请到设置勾选「允许分发测试证书」")
		return nil
	}
	a.setStage("分发到目标")
	return a.deploy(c)
}

// checkCert 定时检查：无证书时按配置决定是否自动签发，到期前自动续期
func (a *App) checkCert(c Config) error {
	a.setStage("检查证书")
	f := a.fileSet(c)
	_, statErr := os.Stat(f["fullchain"])
	if statErr != nil {
		if !c.AutoIssue {
			a.log("尚未生成证书，自动首次签发已关闭；请在概览页点击「立即签发」")
			a.setState(func(s *State) {
				s.LastCertCheck = nowISO()
				s.CertNotAfter = ""
				s.CertDaysLeft = 0
				s.CertCA = ""
			})
			return nil
		}
		a.log("未找到证书，执行首次自动签发")
		err := a.issueAndDeploy(c, false)
		a.setState(func(s *State) { s.LastCertCheck = nowISO() })
		return err
	}
	t, err := certNotAfter(f["fullchain"])
	if err != nil {
		a.setState(func(s *State) {
			s.LastCertCheck = nowISO()
			s.CertNotAfter = ""
			s.CertDaysLeft = 0
		})
		return fmt.Errorf("证书有效期解析失败: %w", err)
	}
	days := int(time.Until(t).Hours() / 24)
	a.setState(func(s *State) {
		s.CertNotAfter = t.Format("2006-01-02 15:04:05")
		s.CertDaysLeft = days
		s.LastCertCheck = nowISO()
	})
	a.log("证书检查：剩余 %d 天（阈值 %d 天）", days, c.RenewDays)
	if changed, reason := a.certConfigChanged(c); changed {
		a.log("%s，重新签发证书", reason)
		return a.issueAndDeploy(c, true)
	}
	if c.AutoRenew && days <= c.RenewDays {
		return a.renewAndDeploy(c, false)
	}
	return nil
}

// needsDeploy 判断最近一次签发/续期之后是否还没有成功分发。
// 输出目录里的证书机构与当前配置不一致时不能重试分发，避免把 staging 证书发给生产服务。
func needsDeploy(st State, c Config) bool {
	if st.CertCA != "" && st.CertCA != c.CA {
		return false
	}
	last := st.LastIssueAt
	if st.LastRenewAt > last {
		last = st.LastRenewAt
	}
	if last == "" {
		return false
	}
	if st.LastDeployAt == "" {
		return true
	}
	return last > st.LastDeployAt
}

// certConfigChanged 判断磁盘上的证书配置（CA/密钥长度/泛域名）是否已与当前设置不一致。
func (a *App) certConfigChanged(c Config) (bool, string) {
	if st := a.getState(); st.CertCA != "" && st.CertCA != c.CA {
		return true, fmt.Sprintf("已签发证书的机构是 %s，当前配置是 %s", st.CertCA, c.CA)
	}
	return a.certConfigMismatch(c)
}
