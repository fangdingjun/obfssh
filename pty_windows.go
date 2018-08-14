package obfssh

import (
	"errors"
	"io"
	"os/exec"
)

func startPty(cmd *exec.Cmd) (io.ReadWriteCloser, error) {
	return nil, errors.New("not implement")
}
