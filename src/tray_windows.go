//go:build windows

package main

import (
	_ "embed"

	"fyne.io/systray"
)

//go:embed assets/dynv6.ico
var trayIcon []byte

// runTray 在 Windows 任务栏右下角显示图标与菜单，阻塞直到用户退出
func runTray(openUI, openDir, onExit, onReady func()) {
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTooltip("Dynv6 管家 - 动态域名与证书")
		mOpen := systray.AddMenuItem("打开界面", "在浏览器中打开 Dynv6 管家")
		mDir := systray.AddMenuItem("打开配置目录", "打开配置与证书目录")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("退出", "停止服务并退出")
		if onReady != nil {
			onReady()
		}
		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					openUI()
				case <-mDir.ClickedCh:
					openDir()
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()
	}, onExit)
}
