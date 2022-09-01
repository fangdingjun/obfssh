package obfssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/fangdingjun/go-log/v5"
	socks "github.com/fangdingjun/socks-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Client is ssh client connection
type Client struct {
	conn      net.Conn
	sshConn   ssh.Conn
	client    *ssh.Client
	listeners []net.Listener
	err       error
	ctx       context.Context
	cancel    context.CancelFunc
	authAgent agent.ExtendedAgent
}

// NewClient create a new ssh Client
//
// addr is server address
//
// conf is the client configure
func NewClient(c net.Conn, config *ssh.ClientConfig, addr string, conf *Conf) (*Client, error) {
	//obfsConn := &TimedOutConn{c, conf.Timeout}
	sshConn, newch, reqs, err := ssh.NewClientConn(c, addr, config)
	if err != nil {
		return nil, err
	}

	sshClient := ssh.NewClient(sshConn, newch, reqs)
	client := &Client{
		conn: c, sshConn: sshConn, client: sshClient,
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	go client.keepAlive(conf.KeepAliveInterval, conf.KeepAliveMax)
	return client, nil
}

// SetAuthAgent set auth agent
func (cc *Client) SetAuthAgent(_agent agent.ExtendedAgent) {
	cc.authAgent = _agent
}

// Client return *ssh.Client
func (cc *Client) Client() *ssh.Client {
	return cc.client
}

// Run wait ssh connection to finish
func (cc *Client) Run() error {
	defer cc.Close()
	defer cc.cancel()

	go cc.registerSignal()

	time.Sleep(1 * time.Second)

	// wait port forward to finish
	if cc.listeners != nil {
		log.Debugf("wait all channel to be done")
		go func() {
			cc.err = cc.sshConn.Wait()
			log.Debugf("connection hang up")
			cc.cancel()
			//close(cc.ch)
		}()
	}
	<-cc.ctx.Done()
	return cc.err
}

func (cc *Client) closeListener() {
	if len(cc.listeners) == 0 {
		return
	}

	// close remote listener may block, because of connection issue
	// so only 1 second to wait
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	wg := &sync.WaitGroup{}
	for _, l := range cc.listeners {
		go func(l net.Listener) {
			log.Debugf("begin to close listener %s", l.Addr().String())
			l.Close()
			log.Debugf("close listener %s done", l.Addr().String())
			wg.Done()
		}(l)
		wg.Add(1)
	}

	go func() {
		wg.Wait()
		cancel()
	}()

	<-ctx.Done()
}

// Close close the ssh connection
// and free all the port forward resources
func (cc *Client) Close() {
	cc.closeListener()

	log.Debugf("close ssh connection")
	cc.sshConn.Close()
	cc.conn.Close()
	log.Debugf("close ssh connection done")
}

// RunCmd run a single command on server
func (cc *Client) RunCmd(cmd string) error {
	go cc.runCmd(cmd)
	return nil
}

func (cc *Client) runCmd(cmd string) error {
	defer cc.cancel()
	log.Debugf("run command %s", cmd)
	session, err := cc.client.NewSession()
	if err != nil {
		log.Debugf("new session error: %s", err.Error())
		cc.err = err
		return err
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stderr = os.Stderr
	session.Stdout = os.Stdout
	if err = session.Run(cmd); err != nil {
		cc.err = err
		return err
	}
	return nil
}

// Shell start a login shell on server
func (cc *Client) Shell() error {
	go cc.shell()
	return nil
}

func (cc *Client) shell() error {
	defer cc.cancel()

	log.Debugf("request new session")
	session, err := cc.client.NewSession()
	if err != nil {
		cc.err = err
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{}

	_console := console.Current()
	defer _console.Reset()

	// this make CTRL+C works
	log.Debugf("turn terminal mode to raw")
	_console.SetRaw()

	ws, _ := _console.Size()

	log.Debugf("request pty")
	if err := session.RequestPty("xterm", int(ws.Height), int(ws.Width), modes); err != nil {
		log.Errorf("request pty error: %s", err.Error())
		cc.err = err
		return err
	}

	if cc.authAgent != nil {
		log.Debugln("request auth agent forwarding")
		if err = agent.RequestAgentForwarding(session); err == nil {
			if err1 := agent.ForwardToAgent(cc.client, cc.authAgent); err1 != nil {
				log.Debugln(err1)
			}
		} else {
			log.Debugln(err)
		}
	}

	// register console change signal
	consoleChange(_console, session)

	session.Stdin = _console
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	log.Debugf("request shell")
	if err := session.Shell(); err != nil {
		log.Errorf("start shell error: %s", err.Error())
		cc.err = err
		return err
	}

	ch := make(chan struct{}, 1)
	go func() {
		if err = session.Wait(); err != nil {
			log.Errorln(err)
			cc.err = err
		}
		log.Debugf("session closed")
		ch <- struct{}{}
	}()

	select {
	case <-ch:
	case <-cc.ctx.Done():
	}
	return nil
}

// AddLocalForward add a local to remote port forward
func (cc *Client) AddLocalForward(local, remote string) error {
	log.Debugf("add local forward %s -> %s", local, remote)
	l, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	cc.listeners = append(cc.listeners, l)
	go func(l net.Listener) {
		//defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				log.Debugf("local listen %s closed", l.Addr())
				return
			}
			log.Debugf("connection accepted from %s", c.RemoteAddr())
			go cc.handleLocalForward(c, remote)
		}
	}(l)

	return nil
}

// AddRemoteForward add a remote to local port forward
func (cc *Client) AddRemoteForward(local, remote string) error {
	log.Debugf("add remote forward %s -> %s", remote, local)
	l, err := cc.client.Listen("tcp", remote)
	if err != nil {
		return err
	}

	cc.listeners = append(cc.listeners, l)
	go func(l net.Listener) {
		//defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				log.Debugf("remote listener %s closed", l.Addr())
				return
			}
			log.Debugf("accept remote forward connection from %s", c.RemoteAddr())
			go cc.handleRemoteForward(c, local)
		}
	}(l)
	return nil
}

// AddDynamicForward add a dynamic port forward
func (cc *Client) AddDynamicForward(local string) error {
	log.Debugf("add dynamic forward %s", local)
	l, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	cc.listeners = append(cc.listeners, l)
	go func(l net.Listener) {
		//defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				log.Debugf("local listener %s closed", l.Addr())
				return
			}
			log.Debugf("accept connection from %s", c.RemoteAddr())
			go cc.handleDynamicForward(c)
		}
	}(l)
	return nil
}

func (cc *Client) handleLocalForward(conn net.Conn, remote string) {
	rconn, err := cc.client.Dial("tcp", remote)
	if err != nil {
		log.Errorf("connect to %s failed: %s", remote, err.Error())
		conn.Close()
		return
	}
	log.Debugf("remote connect to %s success", remote)
	PipeAndClose(rconn, conn)
}

func (cc *Client) handleRemoteForward(conn net.Conn, local string) {
	lconn, err := dialer.Dial("tcp", local)
	if err != nil {
		log.Errorf("connect to %s failed: %s", local, err.Error())
		conn.Close()
		return
	}
	log.Debugf("connect to %s success", local)
	PipeAndClose(conn, lconn)
}

func (cc *Client) handleDynamicForward(conn net.Conn) {
	addr, err := getOriginDst(conn)
	if err == nil {
		if addr.String() != conn.LocalAddr().String() {
			// transparent proxy
			// iptables redirect the packet to this port
			log.Debugf("transparent %s -> %s", conn.RemoteAddr(), addr)
			cc.handleTransparentProxy(conn, addr)
			return
		}
	} else {
		// SO_ORIGNAL_DST failed
		// just ignore it
		log.Debugf("get original destination on %s failed: %s, ignore",
			conn.LocalAddr(), err)
	}

	// socks5 to this port
	log.Debugf("socks %s", conn.RemoteAddr())
	s := socks.Conn{Conn: conn, Dial: cc.client.Dial}
	s.Serve()
}

func (cc *Client) handleTransparentProxy(c net.Conn, addr net.Addr) {
	c2, err := cc.client.Dial("tcp", addr.String())
	if err != nil {
		log.Errorf("%s", err)
		c.Close()
		return
	}
	PipeAndClose(c2, c)
}

func doKeepAlive(conn ssh.Conn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ch := make(chan error, 1)

	go func() {
		_, _, err := conn.SendRequest("keepalive@openssh.org", true, nil)
		ch <- err
	}()

	select {
	case <-ctx.Done():
		return errors.New("keepalive timeout")
	case err := <-ch:
		if err != nil {
			return err
		}
		return nil
	}
}

func (cc *Client) keepAlive(interval time.Duration, maxCount int) {
	count := 0
	c := time.NewTicker(interval)
	defer c.Stop()

	for {
		select {
		case <-cc.ctx.Done():
			return
		case <-c.C:
			if err := doKeepAlive(cc.sshConn, 3*time.Second); err != nil {
				count++
			} else {
				count = 0
			}
			if count >= maxCount {
				cc.err = fmt.Errorf("keep alive detects connection hang up")
				log.Errorf("keep alive hit max count, exit")
				cc.cancel()
				return
			}
		}
	}
}

func (cc *Client) registerSignal() {
	c := make(chan os.Signal, 5)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s1 := <-c:
		cc.err = fmt.Errorf("signal %v", s1)
		log.Errorf("signal %d received, exit", s1)
		//close(cc.ch)
		cc.cancel()
	}
}

// AddDynamicHTTPForward add a http dynamic forward through
//
//	secure channel
func (cc *Client) AddDynamicHTTPForward(addr string) error {
	log.Debugf("add dynamic http listen: %s", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("listen on %s failed, %s", addr, err)
		return err
	}

	cc.listeners = append(cc.listeners, l)

	go func(l net.Listener) {
		// defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				log.Errorf("accept error %s", err)
				break
			}
			go cc.handleHTTPIncoming(c)
		}
	}(l)
	return nil
}

func (cc *Client) handleHTTPIncoming(c net.Conn) {
	//defer c.Close()

	r := bufio.NewReader(c)

	req, err := http.ReadRequest(r)
	if err != nil {
		log.Errorf("read http request error %s", err)
		c.Close()
		return
	}

	if req.Method == "CONNECT" {
		cc.handleConnect(req, c)
		return
	}
	cc.handleHTTPReq(req, c)
}

func (cc *Client) handleConnect(req *http.Request, c net.Conn) {
	log.Debugf("connect to %s", req.RequestURI)

	c1, err := cc.client.Dial("tcp", req.RequestURI)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.0 503 connection failed\r\n\r\n")
		log.Errorf("dial error %s", err)
		c.Close()
		return
	}

	//defer c1.Close()

	fmt.Fprintf(c, "HTTP/1.0 200 connection established\r\n\r\n")
	PipeAndClose(c, c1)
}

func (cc *Client) handleHTTPReq(req *http.Request, c net.Conn) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:80", host)
	}

	log.Debugf("request to %s", host)
	c1, err := cc.client.Dial("tcp", host)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 503 connection failed\r\nConnection: close\r\n\r\n")
		log.Errorf("connection failed %s", err)
		c.Close()
		return
	}
	//defer c1.Close()

	if err = req.Write(c1); err != nil {
		fmt.Fprintf(c, "HTTP/1.1 503 write to server error\r\nConnection: close\r\n\r\n")
		log.Errorf("write request to server error %s", err)
		c.Close()
		c1.Close()
		return
	}
	PipeAndClose(c, c1)
}
