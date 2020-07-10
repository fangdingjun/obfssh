// +build darwin freebsd linux openbsd solaris

package obfssh

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/containerd/console"
	"github.com/fangdingjun/go-log/v5"
	"golang.org/x/crypto/ssh"
)

func consoleChange(_console console.Console, session *ssh.Session) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-ch:
				ws, _ := _console.Size()
				_winCh := windowChange{Rows: uint32(ws.Height), Columns: uint32(ws.Width)}
				d := ssh.Marshal(_winCh)
				ok, err := session.SendRequest("window-change", true, d)
				log.Debugf("send window change request %+v %+v", ok, err)
			}
		}
	}()
}

func newPty() (console.Console, string, error) {
	return console.NewPty()
}

func setProcAttr(attr *syscall.SysProcAttr) {
	attr.Setsid = true
	attr.Setctty = true
}
