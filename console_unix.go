//go:build darwin || freebsd || linux || openbsd || solaris
// +build darwin freebsd linux openbsd solaris

package obfssh

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/console"
	"github.com/fangdingjun/go-log/v5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
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

func setFlag(f *uint32, k uint8, v uint32) {
	v1, ok := termiosMap[k]
	if !ok {
		return
	}
	if v != 0 {
		*f |= v1
		return
	}
	*f &^= v1
}

func applyTermios(flag *unix.Termios, t ssh.TerminalModes) {
	for k, v := range t {
		switch k {
		case ssh.IGNPAR, ssh.PARMRK, ssh.INPCK, ssh.ISTRIP, ssh.INLCR, ssh.IGNCR, ssh.ICRNL, ssh.IUCLC, ssh.IXON, ssh.IXANY, ssh.IXOFF, ssh.IMAXBEL:
			setFlag(&flag.Iflag, k, v)
		case ssh.OPOST, ssh.OLCUC, ssh.ONLCR, ssh.OCRNL, ssh.ONOCR, ssh.ONLRET:
			setFlag(&flag.Oflag, k, v)
		case ssh.CS7, ssh.CS8, ssh.PARENB, ssh.PARODD:
			setFlag(&flag.Cflag, k, v)
		case ssh.ISIG, ssh.ICANON, ssh.XCASE, ssh.ECHO, ssh.ECHOE, ssh.ECHOK, ssh.ECHONL, ssh.ECHOCTL, ssh.ECHOKE, ssh.NOFLSH, ssh.TOSTOP, ssh.PENDIN, ssh.IEXTEN:
			setFlag(&flag.Lflag, k, v)
		case ssh.VEOF, ssh.VEOL, ssh.VEOL2, ssh.VDISCARD, ssh.VDSUSP, ssh.VERASE, ssh.VINTR, ssh.VKILL, ssh.VLNEXT, ssh.VQUIT, ssh.VREPRINT, ssh.VSTART, ssh.VSTATUS, ssh.VSTOP, ssh.VSUSP, ssh.VSWTCH, ssh.VWERASE:
			v1, ok := termiosMap[k]
			if ok {
				flag.Cc[v1] = uint8(v)
			}
		case ssh.TTY_OP_ISPEED:
			flag.Ispeed = v
		case ssh.TTY_OP_OSPEED:
			flag.Ospeed = v
		}
	}
}

func setTermios(fd int, args ssh.TerminalModes) error {
	t1, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}

	log.Debugf("before %+v", t1)
	applyTermios(t1, args)

	err = unix.IoctlSetTermios(fd, unix.TCSETS, t1)
	if err != nil {
		return err
	}

	t1, err = unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}

	log.Debugf("after %+v", t1)

	return nil
}

func setUserEnv(_cmd *exec.Cmd, u *user.User, attr *syscall.SysProcAttr) {
	if u == nil {
		return
	}
	_uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	_gid, _ := strconv.ParseUint(u.Gid, 10, 32)

	_cmd.Env = append(_cmd.Env, fmt.Sprintf("HOME=%s", u.HomeDir))
	_cmd.Env = append(_cmd.Env, fmt.Sprintf("LOGNAME=%s", u.Name))
	_cmd.Dir = u.HomeDir

	if os.Getuid() != 0 {
		return
	}

	if attr.Credential == nil {
		attr.Credential = &syscall.Credential{}
	}

	attr.Credential.Uid = uint32(_uid)
	attr.Credential.Gid = uint32(_gid)
	for _, _env := range _cmd.Env {
		ss := strings.Split(_env, "=")
		if ss[0] == "SSH_AUTH_SOCK" {
			os.Chown(ss[1], int(_uid), int(_gid))
		}
		if ss[0] == "SSH_TTY" {
			os.Chown(ss[1], int(_uid), 0)
		}
	}

}
