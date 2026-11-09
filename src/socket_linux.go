//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// applySocketGroup 把 Socket 属组改为 DYNV6_SOCKET_GROUP（支持组名或数字 GID），
// 以便非 root 网关注入进程按 0660 权限连接。
func applySocketGroup(path string) error {
	raw := strings.TrimSpace(os.Getenv("DYNV6_SOCKET_GROUP"))
	if raw == "" {
		return nil
	}
	var gid uint64
	if v, err := strconv.ParseUint(raw, 10, 32); err == nil {
		gid = v
	} else {
		g, err := user.LookupGroup(raw)
		if err != nil {
			return fmt.Errorf("无法解析组 %q: %w", raw, err)
		}
		v, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("组 %q 的 GID 无效: %w", raw, err)
		}
		gid = v
	}
	return os.Chown(path, -1, int(gid))
}

// peerListener 在 accept 后校验 SO_PEERCRED，避免本机其他用户绕过文件权限伪造网关身份头。
type peerListener struct {
	net.Listener
	logf      func(string, ...any)
	socketGID uint32
}

func newPeerListener(ln net.Listener, logf func(string, ...any)) net.Listener {
	listener := &peerListener{Listener: ln, logf: logf}
	if addr, ok := ln.Addr().(*net.UnixAddr); ok {
		if st, err := os.Stat(addr.Name); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				listener.socketGID = uint32(sys.Gid)
			}
		}
	}
	return listener
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		uid, gid, pid, credErr := unixPeerCred(unixConn)
		socketGID := l.socketGID
		if addr, ok := l.Addr().(*net.UnixAddr); ok {
			if st, err := os.Stat(addr.Name); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					socketGID = uint32(sys.Gid)
				}
			}
		}
		if credErr != nil || !peerAllowed(uid, gid, pid, socketGID) {
			if l.logf != nil {
				l.logf("拒绝未授权的 Socket 连接 uid=%d gid=%d pid=%d: %v", uid, gid, pid, credErr)
			}
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func unixPeerCred(conn *net.UnixConn) (uint32, uint32, int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var uid, gid uint32
	var pid int32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			credErr = e
			return
		}
		uid, gid, pid = cred.Uid, cred.Gid, cred.Pid
	}); err != nil {
		return 0, 0, 0, err
	}
	return uid, gid, pid, credErr
}

func peerAllowed(uid, gid uint32, pid int32, socketGID uint32) bool {
	if uid == 0 || uid == uint32(os.Geteuid()) || gid == uint32(os.Getegid()) {
		return true
	}
	if socketGID != 0 && gid == socketGID {
		return true
	}
	if envIDAllowed("DYNV6_TRUSTED_PEER_UIDS", uid) || envIDAllowed("DYNV6_TRUSTED_PEER_GIDS", gid) {
		return true
	}
	// SO_PEERCRED 只给主属组；这里再读 /proc/<pid>/status 的附加组，
	// 让以附加组身份运行的网关进程也能连接。
	for _, group := range peerGroups(pid) {
		if (socketGID != 0 && group == socketGID) || envIDAllowed("DYNV6_TRUSTED_PEER_GIDS", group) {
			return true
		}
	}
	return false
}

func peerGroups(pid int32) []uint32 {
	if pid <= 0 {
		return nil
	}
	data, err := os.ReadFile("/proc/" + strconv.FormatInt(int64(pid), 10) + "/status")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Groups:") {
			continue
		}
		var out []uint32
		for _, field := range strings.Fields(strings.TrimPrefix(line, "Groups:")) {
			if v, err := strconv.ParseUint(field, 10, 32); err == nil {
				out = append(out, uint32(v))
			}
		}
		return out
	}
	return nil
}

func envIDAllowed(key string, id uint32) bool {
	for _, field := range strings.FieldsFunc(os.Getenv(key), func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	}) {
		if v, err := strconv.ParseUint(field, 10, 32); err == nil && uint32(v) == id {
			return true
		}
	}
	return false
}
