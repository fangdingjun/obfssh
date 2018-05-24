package obfssh

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fangdingjun/go-log"
	socks "github.com/fangdingjun/socks-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Client is ssh client connection
type Client struct {
	conn      net.Conn
	sshConn   ssh.Conn
	client    *ssh.Client
	listeners []net.Listener
	ch        chan struct{}
	err       error
}

// NewClient create a new ssh Client
//
// addr is server address
//
// conf is the client configure
//
//
func NewClient(c net.Conn, config *ssh.ClientConfig, addr string, conf *Conf) (*Client, error) {
	//obfsConn := &TimedOutConn{c, conf.Timeout}
	sshConn, newch, reqs, err := ssh.NewClientConn(c, addr, config)
	if err != nil {
		return nil, err
	}

	sshClient := ssh.NewClient(sshConn, newch, reqs)
	client := &Client{
		conn: c, sshConn: sshConn, client: sshClient,
		ch: make(chan struct{}),
	}
	go client.keepAlive(conf.KeepAliveInterval, conf.KeepAliveMax)
	return client, nil
}

// Client return *ssh.Client
func (cc *Client) Client() *ssh.Client {
	return cc.client
}

// Run wait ssh connection to finish
func (cc *Client) Run() error {
	select {
	case <-time.After(1 * time.Second):
	}
	// wait port forward to finish
	if cc.listeners != nil {
		log.Debugf("wait all channel to be done")
		go cc.registerSignal()
		go func() {
			cc.err = cc.sshConn.Wait()
			log.Debugf("connection hang up")
			//close(cc.ch)
			select {
			case cc.ch <- struct{}{}:
			default:
			}
		}()

		// wait exit signal
		select {
		case <-cc.ch:
			log.Debugf("got signal, exit")
		}
	}
	cc.Close()
	log.Debugf("Done")
	return cc.err
}

func (cc *Client) closeListener() {
	if len(cc.listeners) == 0 {
		return
	}

	// close remote listener may block, because of connection issue
	// so only 1 second to wait

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

	ch := make(chan struct{})
	go func() {
		wg.Wait()
		ch <- struct{}{}
	}()

	select {
	case <-ch:
	case <-time.After(1 * time.Second):
	}
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
func (cc *Client) RunCmd(cmd string) ([]byte, error) {
	log.Debugf("run command %s", cmd)
	session, err := cc.client.NewSession()
	if err != nil {
		log.Debugf("command exited with error: %s", err.Error())
	} else {
		log.Debugf("command exited with no error")
	}

	if err != nil {
		return nil, err
	}
	d, err := session.CombinedOutput(cmd)
	session.Close()
	return d, err
}

// Shell start a login shell on server
func (cc *Client) Shell() error {
	log.Debugf("request new session")
	session, err := cc.client.NewSession()
	if err != nil {
		return err
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// this make CTRL+C works
	log.Debugf("turn terminal mode to raw")
	oldState, _ := terminal.MakeRaw(0)
	w, h, _ := terminal.GetSize(0)
	log.Debugf("request pty")
	if err := session.RequestPty("xterm", h, w, modes); err != nil {
		log.Errorf("request pty error: %s", err.Error())
		log.Debugf("restore terminal mode")
		terminal.Restore(0, oldState)
		return err
	}
	log.Debugf("request shell")
	if err := session.Shell(); err != nil {
		log.Errorf("start shell error: %s", err.Error())
		log.Debugf("restore terminal mode")
		terminal.Restore(0, oldState)
		return err
	}

	session.Wait()
	log.Debugf("session closed")
	terminal.Restore(0, oldState)
	log.Debugf("restore terminal mode")
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

func (cc *Client) keepAlive(interval time.Duration, maxCount int) {
	count := 0
	c := time.NewTicker(interval)
	for {
		select {
		case <-c.C:
			resCh := make(chan error, 1)
			go func(resCh chan error) {
				_, _, err := cc.sshConn.SendRequest("keepalive@openssh.org", true, nil)
				resCh <- err
			}(resCh)
			select {
			case err := <-resCh:
				if err != nil {
					log.Debugf("keep alive error: %s", err.Error())
					count++
				} else {
					count = 0
				}
			case <-time.After(3 * time.Second):
				log.Debugf("keep alive timed out")
				count++
			}

			if count >= maxCount {
				cc.err = fmt.Errorf("keep alive detects connection hang up")
				log.Errorf("keep alive hit max count, exit")
				//cc.sshConn.Close()
				//cc.conn.Close()
				// send exit signal
				//		close(cc.ch)
				select {
				case cc.ch <- struct{}{}:
				default:
				}
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
		select {
		case cc.ch <- struct{}{}:
		default:
		}
	}
}

// AddDynamicHTTPForward add a http dynamic forward through
//  secure channel
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
		c.Close()
		fmt.Fprintf(c, "HTTP/1.0 503 connection failed\r\n\r\n")
		log.Errorf("dial error %s", err)
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
		c.Close()
		fmt.Fprintf(c, "HTTP/1.1 503 connection failed\r\nConnection: close\r\n\r\n")
		log.Errorf("connection failed %s", err)
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
