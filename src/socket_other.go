//go:build !linux

package main

import "net"

// 非 Linux 平台没有 SO_PEERCRED；Windows 本地模式由一次性令牌保护。
func newPeerListener(ln net.Listener, _ func(string, ...any)) net.Listener {
	return ln
}

// 非 Linux 平台没有 Unix Socket 属组概念。
func applySocketGroup(string) error { return nil }
