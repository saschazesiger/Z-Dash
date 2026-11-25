package cloudflare

import (
	"os/exec"
	"syscall"
)

// createNewProcessGroup is CREATE_NEW_PROCESS_GROUP: the child leads a group
// of its own, so that a console signal meant for the app does not reach it.
const createNewProcessGroup = 0x00000200

// configureProc puts cloudflared into a process group of its own. Windows
// has no signal for a whole group, so the group only keeps the app's own
// console signals away from it.
func configureProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// terminateProc ends the child. There is no polite stop to ask a Windows
// process for from outside, so it is killed.
func terminateProc(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
