package obfssh

import (
	"fmt"
	"net"
	"time"

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

		Log(DEBUG, "request channel %s", newch.ChannelType())

		switch newch.ChannelType() {
		case "session":
			go sc.handleSession(newch)
			continue

		case "direct-tcpip":
			go handleDirectTcpip(newch)
			continue
		}

		Log(DEBUG, "reject channel request %s", newch.ChannelType())

		newch.Reject(ssh.UnknownChannelType, "unknown channel type")
	}
}

func (sc *Server) handleGlobalRequest(req <-chan *ssh.Request) {
	for r := range req {

		Log(DEBUG, "global request %s", r.Type)

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

		if r.WantReply {
			r.Reply(false, nil)
		}
	}
}

func serveSFTP(ch ssh.Channel) {
	defer ch.Close()

	server, err := sftp.NewServer(ch)

	if err != nil {
		Log(DEBUG, "start sftp server failed: %s", err)
		return
	}

	if err := server.Serve(); err != nil {
		Log(DEBUG, "sftp server finished with error: %s", err)
		return
	}
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

func (sc *Server) handleSession(newch ssh.NewChannel) {
	ch, req, err := newch.Accept()
	if err != nil {
		Log(ERROR, "%s", err.Error())
		return
	}

	var cmd args

	ret := false

	for r := range req {
		switch r.Type {
		case "subsystem":
			if err := ssh.Unmarshal(r.Payload, &cmd); err != nil {
				ret = false
			} else {
				if cmd.Arg != "sftp" { // only support sftp
					ret = false
				} else {

					ret = true

					Log(DEBUG, "handle sftp request")

					go serveSFTP(ch)
				}
			}
		default:
			ret = false
		}

		Log(DEBUG, "session request %s, reply %v", r.Type, ret)

		if r.WantReply {
			r.Reply(ret, nil)
		}
	}
}

func handleDirectTcpip(newch ssh.NewChannel) {
	var r directTcpipMsg

	data := newch.ExtraData()

	err := ssh.Unmarshal(data, &r)
	if err != nil {
		Log(DEBUG, "invalid ssh parameter")
		newch.Reject(ssh.ConnectionFailed, "invalid argument")
		return
	}

	Log(DEBUG, "create connection to %s:%d", r.Raddr, r.Rport)

	rconn, err := dialer.Dial("tcp", net.JoinHostPort(r.Raddr, fmt.Sprintf("%d", r.Rport)))
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
		Log(ERROR, "parse ssh data error: %s", err)
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
