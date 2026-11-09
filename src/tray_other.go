//go:build !windows

package main

// runTray 只在 Windows 上启用；其他平台不进入托盘分支
func runTray(openUI, openDir, onExit, onReady func()) {
	onExit()
}
