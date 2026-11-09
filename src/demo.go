package main

// 本地 Windows 测试模式使用的示例数据。飞牛生产环境不会启用（无 TRIM_ 环境变量且非 Windows 时关闭）。

func demoConfig() Config {
	return Config{
		Schema:          2,
		Domain:          "example.dynv6.net",
		Token:           "demo-http-token",
		Email:           "me@example.com",
		Wildcard:        true,
		CA:              "letsencrypt",
		KeyLength:       "ec-256",
		DNSSleep:        120,
		RenewDays:       30,
		DDNSIntervalMin: 5,
		CertCheckHours:  12,
		EnableIPv4:      true,
		EnableIPv6:      false,
		IPv4ProbeURL:    "https://ip.3322.net,https://api.ipify.org,https://ipv4.icanhazip.com,https://checkip.amazonaws.com",
		IPv6ProbeURL:    "https://api6.ipify.org,https://ipv6.icanhazip.com",
		AcmeHome:        "${APPDATA}/acme",
		OutputDir:       "${APPDATA}/certs",
		BackupDir:       "${APPDATA}/backup",
		FilePrefix:      "${DOMAIN}",
		FileMode:        "0600",
		AutoDDNS:        true,
		AutoRenew:       true,
		AutoIssue:       false,
		Targets: []Target{
			{ID: "emby", Name: "Emby", Kind: "emby", Enabled: true, Dir: "${OUTPUT}", Filename: "${DOMAIN}.pfx", Mode: "0644"},
			{ID: "plex", Name: "Plex", Kind: "plex", Enabled: true, Dir: "${OUTPUT}", Filename: "${DOMAIN}.p12", Mode: "0644"},
		},
	}
}

func demoTasks() []Task {
	return []Task{
		{ID: "3", Name: "ddns", Status: "ok", StartedAt: "2026-11-09 11:25:03", EndedAt: "2026-11-09 11:25:04", Message: "完成"},
		{ID: "2", Name: "cert-check", Status: "ok", StartedAt: "2026-11-09 09:00:12", EndedAt: "2026-11-09 09:00:13", Message: "完成"},
		{ID: "1", Name: "issue", Status: "ok", StartedAt: "2026-10-12 03:12:44", EndedAt: "2026-10-12 03:14:02", Message: "完成"},
	}
}

func demoStatus() map[string]any {
	return map[string]any{
		"ok": true, "version": Version, "demo": true, "configured": true,
		"env": "windows", "domain": "example.dynv6.net",
		"capabilities":     map[string]bool{"ddns": true, "issue": true, "convert": true},
		"network_hint":     "",
		"paths_check":      map[string]bool{"output": true, "backup": true, "acme_home": true},
		"authorized_paths": []string{},
		"state": State{
			LastIPv4: "203.0.113.10", LastDDNSAt: "2026-11-09 11:25:03",
			LastDDNSAttempt: "2026-11-09 11:25:03",
			LastDDNSResult:  "更新成功", LastCertCheck: "2026-11-09 09:00:12",
			LastIssueAt: "2026-10-12 03:12:44", LastDeployAt: "2026-10-12 03:14:02",
			CertNotAfter: "2027-01-10 03:12:44", CertDaysLeft: 62,
		},
		"tasks": demoTasks(), "busy": false, "current": "",
		"paths": map[string]string{
			"output": "/vol1/1000/dynv6/certs", "backup": "/vol1/1000/dynv6/backup",
			"acme_home": "/vol1/@appdata/dynv6/acme", "config": "本地演示配置",
		},
		"options": map[string]any{"auto_ddns": true, "auto_renew": true, "auto_issue": false, "renew_days": 30, "ca": "letsencrypt", "allow_test_deploy": false},
	}
}

func demoFiles() map[string]any {
	name := "example.dynv6.net"
	items := []map[string]any{
		{"name": name + ".key", "size": 241, "mod_time": "2026-10-12 03:12:44"},
		{"name": name + ".crt", "size": 1834, "mod_time": "2026-10-12 03:12:44"},
		{"name": name + ".chain.crt", "size": 1286, "mod_time": "2026-10-12 03:12:44"},
		{"name": name + ".fullchain.crt", "size": 3120, "mod_time": "2026-10-12 03:12:44"},
		{"name": name + ".p12", "size": 4210, "mod_time": "2026-10-12 03:14:02"},
		{"name": name + ".pfx", "size": 4210, "mod_time": "2026-10-12 03:14:02"},
	}
	return map[string]any{"ok": true, "dir": "/vol1/1000/dynv6/certs", "files": items}
}

func demoDirs() map[string]any {
	return map[string]any{
		"ok": true,
		"roots": []DirRoot{
			{Name: "证书共享目录", Path: "/vol1/1000/dynv6/certs"},
			{Name: "已授权路径", Path: "/vol1/1000/media"},
		},
		"path":   "/vol1/1000/media",
		"parent": "/vol1/1000",
		"dirs": []DirEntry{
			{Name: "certs", Path: "/vol1/1000/media/certs"},
			{Name: "photos", Path: "/vol1/1000/media/photos"},
		},
	}
}

func demoLogs() map[string]any {
	return map[string]any{"ok": true, "lines": []string{
		"[2026-11-09 11:20:01] dynv6 " + Version + " 启动（Windows 本地测试模式）",
		"[2026-11-09 11:20:02] 服务已就绪，访问 http://127.0.0.1:6000/",
		"[2026-11-09 11:25:03] DDNS 更新成功 zone=example.dynv6.net ipv4=203.0.113.10 响应=updated",
		"[2026-11-09 09:00:12] 证书检查：剩余 62 天（阈值 30 天）",
		"[2026-10-12 03:14:02] 证书格式转换完成：PFX（Emby）与 P12（Plex）",
		"[2026-10-12 03:14:02] 分发完成，共 2 个文件",
		"提示：这是演示数据。真实签发/续期需要在飞牛上安装 fpk 后执行。",
	}}
}
