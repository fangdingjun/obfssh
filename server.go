package obfssh

import (
	"fmt"
	"github.com/golang/crypto/ssh"
	"github.com/golang/crypto/ssh/terminal"
	//"log"
	"net"
)

// Server is server connection
type Server struct {
	conn           net.Conn
	sshConn        *ssh.ServerConn
	forwardedPorts map[string]net.Listener
	exitCh         chan int
}

// NewServer create a new struct for Server
//
// c is net.Conn
//
// config is &ssh.ServerConfig
//
// method is obfs encrypt method, value is rc4, aes or none or ""
//
// key is obfs encrypt key
//
// conf is the server configure
//
// if set method to none or "", means disable obfs encryption, when the obfs is disabled,
// the server can accept connection from standard ssh client, like OpenSSH client
//
func NewServer(c net.Conn, config *ssh.ServerConfig, conf *Conf) (*Server, error) {
	wc, err := NewObfsConn(c, conf.ObfsMethod, conf.ObfsKey, true)
	if err != nil {
		return nil, err
	}
	sshConn, ch, req, err := ssh.NewServerConn(wc, config)
	if err != nil {
		return nil, err
	}

	if conf.DisableObfsAfterHandshake {
		wc.DisableObfs()
	}

	sc := &Server{conn: c,
		sshConn:        sshConn,
		forwardedPorts: map[string]net.Listener{},
		exitCh:         make(chan int)}
	go sc.handleGlobalRequest(req)
	go sc.handleNewChannelRequest(ch)
	return sc, nil
}

// Run waits for server connection finish
func (sc *Server) Run() {
	sc.sshConn.Wait()
	Log(DEBUG, "ssh connection closed")
	sc.close()
}

func (sc *Server) close() {
	Log(DEBUG, "close connection")
	sc.sshConn.Close()
	//Log(DEBUG, "close listener")
	for _, l := range sc.forwardedPorts {
		Log(DEBUG, "close listener %s", l.Addr())
		l.Close()
	}
}

func (sc *Server) handleNewChannelRequest(ch <-chan ssh.NewChannel) {
	for newch := range ch {
		switch newch.ChannelType() {
		case "session":
			//go sc.handleSession(newch)
			//continue
		case "direct-tcpip":
			go handleDirectTcpip(newch)
			continue
		}
		Log(DEBUG, "reject channel request %s", newch.ChannelType())
		newch.Reject(ssh.UnknownChannelType, "unknown channel type")
		//channel, request, err := newch.Accept()
	}
}

func (sc *Server) handleGlobalRequest(req <-chan *ssh.Request) {
	for r := range req {
		switch r.Type {
		case "tcpip-forward":
			Log(DEBUG, "request port forward")
			go sc.handleTcpipForward(r)
			continue
		case "cancel-tcpip-forward":
			Log(DEBUG, "request cancel port forward")
			go sc.handleCancelTcpipForward(r)
			continue
		}
		Log(DEBUG, "global request %s", r.Type)
		if r.WantReply {
			r.Reply(false, nil)
		}
	}
}

func (sc *Server) handleChannelRequest(req <-chan *ssh.Request) {
	ret := false
	for r := range req {
		switch r.Type {
		case "shell":
			ret = true
		case "pty-req":
			ret = true
		case "env":
			ret = true
		case "exec":
			ret = false
		case "subsystem":
		default:
			ret = false
		}
		if r.WantReply {
			r.Reply(ret, nil)
		}
	}
}

type directTcpipMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

func (sc *Server) handleSession(newch ssh.NewChannel) {
	ch, req, err := newch.Accept()
	if err != nil {
		Log(ERROR, "%s", err.Error())
		return
	}
	go sc.handleChannelRequest(req)
	term := terminal.NewTerminal(ch, "shell>")
	defer ch.Close()
	for {
		line, err := term.ReadLine()
		if err != nil {
			break
		}
		term.Write([]byte(line))
		term.Write([]byte("\n"))
	}
}

func handleDirectTcpip(newch ssh.NewChannel) {
	data := newch.ExtraData()
	var r directTcpipMsg
	err := ssh.Unmarshal(data, &r)
	if err != nil {
		Log(DEBUG, "invalid ssh parameter")
		newch.Reject(ssh.ConnectionFailed, "invalid argument")
		return
	}
	Log(DEBUG, "create connection to %s:%d", r.Raddr, r.Rport)
	rconn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", r.Raddr, r.Rport))
	if err != nil {
		Log(ERROR, "%s", err.Error())
		newch.Reject(ssh.ConnectionFailed, "invalid argument")
		return
	}
	channel, requests, err := newch.Accept()
	if err != nil {
		rconn.Close()
		Log(ERROR, "%s", err.Error())
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
		Log(ERROR, "invalid ssh parameter for cancel port forward")
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
		Log(ERROR, "parse ssh data error: %s", err.Error)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	if addr.Port > 65535 || addr.Port < 0 {
		Log(ERROR, "invalid port %d", addr.Port)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	ip := net.ParseIP(addr.Addr)
	if ip == nil {
		Log(ERROR, "invalid ip %d", addr.Port)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	k := fmt.Sprintf("%s:%d", addr.Addr, addr.Port)

	if _, ok := sc.forwardedPorts[k]; ok {
		// port in use
		Log(ERROR, "port in use: %s", k)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	//Log(DEBUG, "get request for addr: %s, port: %d", addr.Addr, addr.Port)

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: int(addr.Port)})
	if err != nil {
		// listen failed
		Log(ERROR, "%s", err.Error())
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	a1 := l.Addr()
	Log(DEBUG, "Listening port %s", a1)
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
			Log(ERROR, "%s", err.Error())
			return
		}
		Log(DEBUG, "accept connection from %s", c.RemoteAddr())
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
				Log(ERROR, "forward port failed: %s", err.Error())
				c.Close()
				return
			}
			go ssh.DiscardRequests(r)
			PipeAndClose(c, ch)
		}(c)
	}
}
