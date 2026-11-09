//go:build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
)

func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func setProcessGroup(cmd *exec.Cmd) {}

func killProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}
