// +build windows

package obfssh

import (
	"errors"
	"syscall"

	"github.com/containerd/console"
	"golang.org/x/crypto/ssh"
)

func consoleChange(_console console.Console, session *ssh.Session) {

}

func newPty() (console.Console, string, error) {
	return nil, "", errors.New("not supported")
}

func setProcAttr(attr *syscall.SysProcAttr) {
}

func setTermios(fd int, args ssh.TerminalModes) error {
	return errors.New("not supported")
}
