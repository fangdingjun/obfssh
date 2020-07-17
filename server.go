package obfssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/fangdingjun/go-log/v5"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is server connection
type Server struct {
	conn           net.Conn
	sshConn        *ssh.ServerConn
	forwardedPorts map[string]net.Listener
	exitCh         chan struct{}
}

// NewServer create a new struct for Server
//
// c is net.Conn
//
// config is &ssh.ServerConfig
//
// conf is the server configure
//
//
func NewServer(c net.Conn, config *ssh.ServerConfig, conf *Conf) (*Server, error) {
	sshConn, ch, req, err := ssh.NewServerConn(&TimedOutConn{c, 15 * 60 * time.Second}, config)
	if err != nil {
		return nil, err
	}

	sc := &Server{
		conn:           c,
		sshConn:        sshConn,
		forwardedPorts: map[string]net.Listener{},
		exitCh:         make(chan struct{})}
	go sc.handleGlobalRequest(req)
	go sc.handleNewChannelRequest(ch)
	return sc, nil
}

// Run waits for server connection finish
func (sc *Server) Run() {
	sc.sshConn.Wait()
	log.Debugf("ssh connection closed")
	sc.close()
}

func (sc *Server) close() {
	log.Debugf("close connection")
	sc.sshConn.Close()
	//log.Debugf( "close listener")
	for _, l := range sc.forwardedPorts {
		log.Debugf("close listener %s", l.Addr())
		l.Close()
	}
}

func (sc *Server) handleNewChannelRequest(ch <-chan ssh.NewChannel) {
	for newch := range ch {

		log.Debugf("request channel %s", newch.ChannelType())

		switch newch.ChannelType() {
		case "session":
			go sc.handleSession(newch)
			continue

		case "direct-tcpip":
			go handleDirectTcpip(newch)
			continue
		}

		log.Errorf("reject channel request %s", newch.ChannelType())

		newch.Reject(ssh.UnknownChannelType, "unknown channel type")
	}
}

func (sc *Server) handleGlobalRequest(req <-chan *ssh.Request) {
	for r := range req {

		log.Debugf("global request %s", r.Type)

		switch r.Type {
		case "tcpip-forward":
			log.Debugf("request port forward")
			go sc.handleTcpipForward(r)
			continue
		case "cancel-tcpip-forward":
			log.Debugf("request cancel port forward")
			go sc.handleCancelTcpipForward(r)
			continue
		}

		if r.WantReply {
			r.Reply(false, nil)
		}
	}
}

func serveSFTP(ch ssh.Channel) {
	defer ch.Close()

	server, err := sftp.NewServer(ch)

	if err != nil {
		log.Debugf("start sftp server failed: %s", err)
		ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 127}))
		return
	}

	if err := server.Serve(); err != nil {
		log.Debugf("sftp server finished with error: %s", err)
		ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 127}))
		return
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 0}))
}

type directTcpipMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

type args struct {
	Arg string
}

type envArgs struct {
	Name  string
	Value string
}

type exitStatus struct {
	Status uint32
}

type ptyReq struct {
	Term    string
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
	Mode    string
}

type windowChange struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func parseTerminalModes(s string) ssh.TerminalModes {
	// log.Debugf("%x", s)
	s1 := []byte(s)
	t := ssh.TerminalModes{}
	for i := 0; i < len(s1); i += 5 {
		k := uint8(s1[i])
		if k == 0 {
			break
		}
		v := binary.BigEndian.Uint32(s1[i+1 : i+5])
		t[k] = v
		// log.Debugf("k %d, v %d", k, v)
	}
	return t
}

type session struct {
	ch       ssh.Channel
	env      []string
	_console console.Console
	ptsname  string
	cmd      *exec.Cmd
	user     string
}

func (s *session) handleSubsystem(payload []byte) bool {
	var _cmd args
	if err := ssh.Unmarshal(payload, &_cmd); err != nil {
		log.Errorln(err)
		return false
	}

	if _cmd.Arg != "sftp" { // only support sftp
		log.Debugln("subsystem", _cmd.Arg, "not support")
		return false
	}
	log.Debugf("handle sftp request")
	go serveSFTP(s.ch)
	return true
}

func (s *session) handleShell() bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		s.env = append(s.env, fmt.Sprintf("SHELL=powershell"))
		cmd = exec.Command("powershell")
	} else {
		s.env = append(s.env, fmt.Sprintf("SHELL=/bin/bash"))
		cmd = exec.Command("/bin/bash", "-l")
	}
	s.cmd = cmd
	cmd.Env = s.env
	go handleShell(cmd, s.ch, s._console, s.ptsname, s.user)
	return true
}

func (s *session) handleExec(payload []byte) bool {
	var _cmd args
	var cmd *exec.Cmd
	if err := ssh.Unmarshal(payload, &_cmd); err != nil {
		log.Errorln(err)
		return false
	}
	log.Infoln("execute command", _cmd.Arg)
	if runtime.GOOS == "windows" {
		s.env = append(s.env, fmt.Sprintf("SHELL=powershell"))
		cmd = exec.Command("powershell", "-Command", _cmd.Arg)
	} else {
		s.env = append(s.env, fmt.Sprintf("SHELL=/bin/bash"))
		cmd = exec.Command("/bin/bash", "-c", _cmd.Arg)
	}
	s.cmd = cmd
	cmd.Env = s.env
	go handleShell(cmd, s.ch, s._console, s.ptsname, s.user)
	return true
}

func (s *session) handlePtyReq(payload []byte) bool {
	var _ptyReq ptyReq
	var err error
	if err = ssh.Unmarshal(payload, &_ptyReq); err != nil {
		log.Errorln(err)
		return false
	}

	log.Debugf("pty req Rows: %d, Columns: %d, Mode: %x", _ptyReq.Rows, _ptyReq.Columns, _ptyReq.Mode)

	termios := parseTerminalModes(_ptyReq.Mode)
	log.Debugf("parsed terminal mode %+v", termios)

	s._console, s.ptsname, err = newPty()
	if err != nil {
		log.Errorln(err)
		return false
	}

	log.Debugf("allocate pty %s", s.ptsname)
	log.Debugf("set termios")
	if err1 := setTermios(int(s._console.Fd()), termios); err1 != nil {
		log.Errorln(err)
		return false
	}

	s.env = append(s.env, fmt.Sprintf("SSH_TTY=%s", s.ptsname))
	s.env = append(s.env, fmt.Sprintf("TERM=%s", _ptyReq.Term))

	ws, err := s._console.Size()
	log.Debugf("current console %+v", ws)
	ws.Height = uint16(_ptyReq.Rows)
	ws.Width = uint16(_ptyReq.Columns)
	if err = s._console.Resize(ws); err != nil {
		log.Errorln(err)
		return false
	}
	return true
}

func (s *session) handleEnv(payload []byte) bool {
	var arg envArgs
	if err := ssh.Unmarshal(payload, &arg); err != nil {
		log.Errorln(err)
		return false
	}
	log.Debugf("got env %s=%s", arg.Name, arg.Value)
	s.env = append(s.env, fmt.Sprintf("%s=%s", arg.Name, arg.Value))
	return true
}

func (s *session) handleWindowChange(payload []byte) bool {
	var _windowChange windowChange
	if err := ssh.Unmarshal(payload, &_windowChange); err != nil {
		log.Errorln(err)
		return false
	}
	log.Debugf("window change %+v", _windowChange)
	if s._console == nil {
		// ignore
		return true
	}

	ws, err := s._console.Size()
	if err != nil {
		log.Errorln(err)
		return false
	}

	log.Debugf("current console %+v", ws)
	ws.Height = uint16(_windowChange.Rows)
	ws.Width = uint16(_windowChange.Columns)
	if err := s._console.Resize(ws); err != nil {
		log.Errorln(err)
		return false
	}
	return true
}

func (sc *Server) handleSession(newch ssh.NewChannel) {
	ch, req, err := newch.Accept()
	if err != nil {
		log.Errorf("%s", err.Error())
		return
	}

	sess := &session{ch: ch, user: sc.sshConn.User()}

	for r := range req {
		ret := false
		switch r.Type {
		case "subsystem":
			ret = sess.handleSubsystem(r.Payload)
		case "shell":
			ret = sess.handleShell()
		case "exec":
			ret = sess.handleExec(r.Payload)
		case "pty-req":
			ret = sess.handlePtyReq(r.Payload)
		case "env":
			ret = sess.handleEnv(r.Payload)
		case "window-change":
			ret = sess.handleWindowChange(r.Payload)
		case "signal":
			log.Debugln("got signal")
			ret = true
		default:
		}

		log.Debugf("session request %s, reply %v", r.Type, ret)

		if r.WantReply {
			r.Reply(ret, nil)
		}
	}

	if sess.cmd != nil && sess.cmd.Process != nil {
		log.Debugf("kill the running process %s", sess.cmd.Args)
		p := sess.cmd.Process
		if err := p.Kill(); err != nil {
			log.Debugln(err)
		}
		time.Sleep(100 * time.Millisecond)
		if err := p.Signal(os.Kill); err != nil {
			log.Debugln(err)
		}
	}

	log.Debugln("session ended.")
}

func handleShell(cmd *exec.Cmd, ch ssh.Channel, _console console.Console, ptsname string, _user string) {
	defer func() {
		ch.Close()
		if _console != nil {
			_console.Close()
		}
	}()

	var err error

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	_u, err := user.Lookup(_user)
	if err != nil {
		log.Errorln(err)
	}

	setUserEnv(cmd, _u, cmd.SysProcAttr)

	if _console != nil {
		_tty, err := os.OpenFile(ptsname, syscall.O_RDWR|syscall.O_NOCTTY, 0600)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer _tty.Close()
		cmd.Stderr = _tty
		cmd.Stdout = _tty
		cmd.Stdin = _tty

		setProcAttr(cmd.SysProcAttr)

		go io.Copy(ch, _console)
		go io.Copy(_console, ch)
	} else {
		cmd.Stderr = ch
		cmd.Stdout = ch
		// cmd.Stdin = ch

		in, err := cmd.StdinPipe()
		if err != nil {
			ch.SendRequest("exit-status", false,
				ssh.Marshal(exitStatus{Status: 127}))
			return
		}
		go func() {
			defer in.Close()
			io.Copy(in, ch)

		}()
	}
	if err := cmd.Start(); err != nil {
		log.Debugln("start command ", err)
		ch.SendRequest("exit-status", false,
			ssh.Marshal(exitStatus{Status: 126}))
		return
	}

	code := 0
	if err = cmd.Wait(); err != nil {
		log.Debugln(err)
		if exiterr, ok := err.(*exec.ExitError); ok {
			if s, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				code = s.ExitStatus()
			}
		}
	}
	cmd.Process = nil
	ch.SendRequest("exit-status", false,
		ssh.Marshal(exitStatus{Status: uint32(code)}))
}

func handleDirectTcpip(newch ssh.NewChannel) {
	var r directTcpipMsg

	data := newch.ExtraData()

	err := ssh.Unmarshal(data, &r)
	if err != nil {
		log.Errorln("invalid ssh parameter")
		newch.Reject(ssh.ConnectionFailed, "invalid argument")
		return
	}

	log.Debugf("create connection to %s:%d", r.Raddr, r.Rport)

	rconn, err := dialer.Dial("tcp", net.JoinHostPort(r.Raddr, fmt.Sprintf("%d", r.Rport)))
	if err != nil {
		log.Errorf("%s", err.Error())
		newch.Reject(ssh.ConnectionFailed, "invalid argument")
		return
	}

	channel, requests, err := newch.Accept()
	if err != nil {
		rconn.Close()
		log.Errorf("%s", err.Error())
		return
	}

	//log.Println("forward")
	go ssh.DiscardRequests(requests)

	PipeAndClose(channel, rconn)
}

type tcpipForwardAddr struct {
	Addr string
	Port uint32
}

func (sc *Server) handleCancelTcpipForward(req *ssh.Request) {
	var a tcpipForwardAddr

	if err := ssh.Unmarshal(req.Payload, &a); err != nil {
		log.Errorf("invalid ssh parameter for cancel port forward")
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	k := fmt.Sprintf("%s:%d", a.Addr, a.Port)
	if l, ok := sc.forwardedPorts[k]; ok {
		l.Close()
		delete(sc.forwardedPorts, k)
	}

	if req.WantReply {
		req.Reply(true, nil)
	}
}

func (sc *Server) handleTcpipForward(req *ssh.Request) {
	var addr tcpipForwardAddr
	if err := ssh.Unmarshal(req.Payload, &addr); err != nil {
		log.Errorf("parse ssh data error: %s", err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	if addr.Port > 65535 || addr.Port < 0 {
		log.Errorf("invalid port %d", addr.Port)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	ip := net.ParseIP(addr.Addr)
	if ip == nil {
		log.Errorf("invalid ip %d", addr.Port)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	k := fmt.Sprintf("%s:%d", addr.Addr, addr.Port)

	if _, ok := sc.forwardedPorts[k]; ok {
		// port in use
		log.Errorf("port in use: %s", k)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	//log.Debugf( "get request for addr: %s, port: %d", addr.Addr, addr.Port)

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: int(addr.Port)})
	if err != nil {
		// listen failed
		log.Errorf("%s", err.Error())
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	a1 := l.Addr()
	log.Infof("Listening port %s", a1)
	p := struct {
		Port uint32
	}{
		uint32(a1.(*net.TCPAddr).Port),
	}

	sc.forwardedPorts[k] = l

	if req.WantReply {
		req.Reply(true, ssh.Marshal(p))
	}

	for {
		c, err := l.Accept()
		if err != nil {
			log.Debugf("%s", err.Error())
			return
		}
		log.Infof("accept connection from %s", c.RemoteAddr())
		go func(c net.Conn) {
			laddr := c.LocalAddr()
			raddr := c.RemoteAddr()
			a2 := struct {
				laddr string
				lport uint32
				raddr string
				rport uint32
			}{
				addr.Addr,
				uint32(laddr.(*net.TCPAddr).Port),
				raddr.(*net.TCPAddr).IP.String(),
				uint32(raddr.(*net.TCPAddr).Port),
			}
			ch, r, err := sc.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(a2))
			if err != nil {
				log.Errorf("forward port failed: %s", err.Error())
				c.Close()
				return
			}
			go ssh.DiscardRequests(r)
			PipeAndClose(c, ch)
		}(c)
	}
}
