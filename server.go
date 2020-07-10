package obfssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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

func (sc *Server) handleSession(newch ssh.NewChannel) {
	ch, req, err := newch.Accept()
	if err != nil {
		log.Errorf("%s", err.Error())
		return
	}

	ret := false

	var _cmd args
	var cmd *exec.Cmd
	var env []string
	var _ptyReq ptyReq
	var _windowChange windowChange
	var _console console.Console
	var ptsname string

	for r := range req {
		switch r.Type {
		case "subsystem":
			if err := ssh.Unmarshal(r.Payload, &_cmd); err == nil {
				if _cmd.Arg == "sftp" { // only support sftp
					ret = true
					log.Debugf("handle sftp request")
					go serveSFTP(ch)
				} else {
					ret = false
					log.Debugln("subsystem", _cmd.Arg, "not support")
				}
			} else {
				ret = false
				log.Debugln("get subsystem arg error", err)
			}
		case "shell":
			ret = true
			if runtime.GOOS == "windows" {
				cmd = exec.Command("powershell")
			} else {
				cmd = exec.Command("bash", "-l")
			}
			cmd.Env = env
			go handleShell(cmd, ch, _console, ptsname)
		case "signal":
			log.Debugln("got signal")
			ret = true
		case "exec":
			ret = true
			if err = ssh.Unmarshal(r.Payload, &_cmd); err == nil {
				log.Infoln("execute command", _cmd.Arg)
				if runtime.GOOS == "windows" {
					cmd = exec.Command("powershell", "-Command", _cmd.Arg)
				} else {
					cmd = exec.Command("bash", "-c", _cmd.Arg)
				}
				cmd.Env = env
				//cmd.Stdin = ch
				go handleCommand(cmd, ch)
			} else {
				log.Debugln(err)
				ret = false
			}
		case "pty-req":
			ret = true
			err = ssh.Unmarshal(r.Payload, &_ptyReq)
			if err != nil {
				log.Errorln(err)
				ret = false
			}
			log.Debugf("pty req %+v", _ptyReq)
			if err == nil && (runtime.GOOS == "unix" || runtime.GOOS == "linux") {
				_console, ptsname, err = console.NewPty()
				if err == nil {
					log.Debugf("allocate pty %s", ptsname)
					env = append(env, fmt.Sprintf("SSH_TTY=%s", ptsname))
					ws, err := _console.Size()
					if err != nil {
						log.Errorln(err)
					} else {
						log.Debugf("current console %+v", ws)
						ws.Height = uint16(_ptyReq.Rows)
						ws.Width = uint16(_ptyReq.Columns)
						if err = _console.Resize(ws); err != nil {
							log.Errorln(err)
						}
					}
				} else {
					log.Errorln(err)
				}
			}
		case "env":
			var arg envArgs
			ret = true
			if err = ssh.Unmarshal(r.Payload, &arg); err == nil {
				log.Debugf("got env %s=%s", arg.Name, arg.Value)
				env = append(env, fmt.Sprintf("%s=%s", arg.Name, arg.Value))
			} else {
				log.Debugln("parse env failed", err)
				ret = false
			}
		case "window-change":
			ret = true
			err = ssh.Unmarshal(r.Payload, &_windowChange)
			if err != nil {
				ret = false
				log.Errorln(err)
			}
			if err == nil && _console != nil {
				ws, err := _console.Size()
				if err != nil {
					log.Errorln(err)
				} else {
					log.Debugf("current console %+v", ws)
					ws.Height = uint16(_windowChange.Rows)
					ws.Width = uint16(_windowChange.Columns)
					if err = _console.Resize(ws); err != nil {
						log.Errorln(err)
					}
				}
			}
			log.Debugf("window change %+v", _windowChange)
		default:
			ret = false
		}

		log.Debugf("session request %s, reply %v", r.Type, ret)

		if r.WantReply {
			r.Reply(ret, nil)
		}
	}
}

func handleShell(cmd *exec.Cmd, ch ssh.Channel, _console console.Console, ptsname string) {
	defer func() {
		ch.Close()
		if _console != nil {
			_console.Close()
		}
	}()

	var err error

	log.Infoln("start shell")

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
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setctty = true
		// cmd.SysProcAttr.Ctty = int(_tty.Fd())

		go io.Copy(ch, _console)
		go io.Copy(_console, ch)
	} else {
		cmd.Stderr = ch
		cmd.Stdout = ch

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
	ch.SendRequest("exit-status", false,
		ssh.Marshal(exitStatus{Status: uint32(code)}))
}

func handleCommand(cmd *exec.Cmd, ch ssh.Channel) {
	defer ch.Close()

	cmd.Stdout = ch
	cmd.Stderr = ch
	//log.Debugln("execute command", cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		log.Debugln(err)
		ch.SendRequest("exit-status", false,
			ssh.Marshal(exitStatus{Status: 127}))
		return
	}
	go func() {
		defer in.Close()
		io.Copy(in, ch)
	}()
	code := 0
	if err := cmd.Run(); err != nil {
		log.Debugln(err)
		if exiterr, ok := err.(*exec.ExitError); ok {
			if s, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				code = s.ExitStatus()
			}
		}
	}
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
