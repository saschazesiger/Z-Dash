//go:build !windows

package cloudflare

import (
	"os/exec"
	"syscall"
)

// configureProc puts cloudflared into a process group of its own, so that
// stopping it stops what it started and a console signal meant for the app
// does not reach it twice.
func configureProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateProc asks the process group to shut down cleanly.
func terminateProc(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	return nil
}
