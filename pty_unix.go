// +build linux darwin

package obfssh

import (
	"io"
	"os/exec"

	"github.com/kr/pty"
)

func startPty(cmd *exec.Cmd) (io.ReadWriteCloser, error) {
	return pty.Start(cmd)
}
