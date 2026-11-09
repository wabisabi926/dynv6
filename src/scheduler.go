package main

import "time"

func (a *App) startScheduler() {
	go func() {
		// 启动后稍等再跑第一次，避开安装/重启瞬间
		time.Sleep(5 * time.Second)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		a.tick()
		for range ticker.C {
			a.tick()
		}
	}()
}

func (a *App) tick() {
	c := a.getConfig()
	if c.Domain == "" {
		return
	}
	st := a.getState()
	// 按 lane 判断：证书任务耗时长，不能再挡住 DDNS 的定时触发
	if c.AutoDDNS && c.Token != "" && !a.laneBusyNow("ddns") && due(st.LastDDNSAttempt, time.Duration(c.DDNSIntervalMin)*time.Minute) {
		a.startTask("ddns", "ddns", func(c Config) error { return a.runDDNS(false) })
	}
	if (c.AutoRenew || c.AutoIssue) && !a.laneBusyNow("cert") && due(st.LastCertCheck, time.Duration(c.CertCheckHours)*time.Hour) {
		a.startTask("cert-check", "cert", a.checkCert)
	}
	// 已签发/续期但分发失败时，按 30 分钟退避重试，不必等到下一次续期；
	// 证书机构/密钥长度/泛域名与当前配置不一致时先等重新签发，避免分发旧证书。
	if !a.laneBusyNow("cert") && needsDeploy(st, c) && !a.stagingDeployBlocked(c) && due(st.LastDeployAttempt, 30*time.Minute) {
		if changed, _ := a.certConfigChanged(c); !changed {
			a.startTask("deploy-retry", "cert", a.convertAndDeploy)
		}
	}
}
