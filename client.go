package obfssh

import (
	socks "github.com/fangdingjun/socks-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Client is ssh client connection
type Client struct {
	conn      net.Conn
	sshConn   ssh.Conn
	client    *ssh.Client
	listeners []net.Listener
	ch        chan int
}

// NewClient create a new ssh Client
//
// addr is server address
//
// method is obfs encrypt method, value is rc4, aes or none or ""
//
// key is obfs encrypt key
//
// conf is the client configure
//
// if set method to none or "", means disable the obfs,
// when the obfs is disabled, the client can connect to standard ssh server, like OpenSSH server
//
func NewClient(c net.Conn, config *ssh.ClientConfig, addr string, conf *Conf) (*Client, error) {
	Log(DEBUG, "create obfs conn with method %s", conf.ObfsMethod)
	obfsConn, err := NewObfsConn(&TimedOutConn{c, conf.Timeout}, conf.ObfsMethod, conf.ObfsKey, false)
	if err != nil {
		return nil, err
	}
	sshConn, newch, reqs, err := ssh.NewClientConn(obfsConn, addr, config)
	if err != nil {
		return nil, err
	}

	if conf.DisableObfsAfterHandshake {
		obfsConn.DisableObfs()
	}

	sshClient := ssh.NewClient(sshConn, newch, reqs)
	client := &Client{
		conn: c, sshConn: sshConn, client: sshClient,
		ch: make(chan int),
	}
	go client.keepAlive(conf.KeepAliveInterval, conf.KeepAliveMax)
	return client, nil
}

// Client return *ssh.Client
func (cc *Client) Client() *ssh.Client {
	return cc.client
}

// Run wait ssh connection to finish
func (cc *Client) Run() {
	select {
	case <-time.After(1 * time.Second):
	}
	// wait port forward to finish
	if cc.listeners != nil {
		Log(DEBUG, "wait all channel to be done")
		go cc.registerSignal()
		go func() {
			cc.sshConn.Wait()
			select {
			case cc.ch <- 1:
			default:
			}
		}()

		// wait exit signal
		select {
		case <-cc.ch:
			Log(INFO, "got signal, exit")
		}
	}
	Log(DEBUG, "Done")
	cc.Close()
}

// Close close the ssh connection
// and free all the port forward resources
func (cc *Client) Close() {
	for _, l := range cc.listeners {
		Log(INFO, "close the listener %s", l.Addr())
		l.Close()
	}
	//Log(DEBUG, "close ssh connection")
	//cc.sshConn.Close()
}

// RunCmd run a single command on server
func (cc *Client) RunCmd(cmd string) ([]byte, error) {
	Log(INFO, "run command %s", cmd)
	session, err := cc.client.NewSession()
	if err != nil {
		Log(DEBUG, "command exited with error: %s", err.Error())
	} else {
		Log(DEBUG, "command exited with no error")
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
	Log(DEBUG, "request new session")
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
	Log(DEBUG, "turn terminal mode to raw")
	oldState, _ := terminal.MakeRaw(0)
	w, h, _ := terminal.GetSize(0)
	Log(DEBUG, "request pty")
	if err := session.RequestPty("xterm", h, w, modes); err != nil {
		Log(ERROR, "request pty error: %s", err.Error())
		Log(DEBUG, "restore terminal mode")
		terminal.Restore(0, oldState)
		return err
	}
	Log(DEBUG, "request shell")
	if err := session.Shell(); err != nil {
		Log(ERROR, "start shell error: %s", err.Error())
		Log(DEBUG, "restore terminal mode")
		terminal.Restore(0, oldState)
		return err
	}

	session.Wait()
	Log(DEBUG, "session closed")
	terminal.Restore(0, oldState)
	Log(DEBUG, "restore terminal mode")
	return nil
}

// AddLocalForward add a local to remote port forward
func (cc *Client) AddLocalForward(local, remote string) error {
	Log(DEBUG, "add local forward %s -> %s", local, remote)
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
				Log(DEBUG, "local listen %s closed", l.Addr())
				return
			}
			Log(DEBUG, "connection accepted from %s", c.RemoteAddr())
			go cc.handleLocalForward(c, remote)
		}
	}(l)

	return nil
}

// AddRemoteForward add a remote to local port forward
func (cc *Client) AddRemoteForward(local, remote string) error {
	Log(DEBUG, "add remote forward %s -> %s", remote, local)
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
				Log(DEBUG, "remote listener %s closed", l.Addr())
				return
			}
			Log(DEBUG, "accept remote forward connection from %s", c.RemoteAddr())
			go cc.handleRemoteForward(c, local)
		}
	}(l)
	return nil
}

// AddDynamicForward add a dynamic port forward
func (cc *Client) AddDynamicForward(local string) error {
	Log(DEBUG, "add dynamic forward %s", local)
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
				Log(DEBUG, "local listener %s closed", l.Addr())
				return
			}
			Log(DEBUG, "accept connection from %s", c.RemoteAddr())
			go cc.handleDynamicForward(c)
		}
	}(l)
	return nil
}

func (cc *Client) handleLocalForward(conn net.Conn, remote string) {
	rconn, err := cc.client.Dial("tcp", remote)
	if err != nil {
		Log(ERROR, "connect to %s failed: %s", remote, err.Error())
		conn.Close()
		return
	}
	Log(DEBUG, "remote connect to %s success", remote)
	PipeAndClose(rconn, conn)
}

func (cc *Client) handleRemoteForward(conn net.Conn, local string) {
	lconn, err := net.Dial("tcp", local)
	if err != nil {
		Log(ERROR, "connect to %s failed: %s", local, err.Error())
		conn.Close()
		return
	}
	Log(DEBUG, "connect to %s success", local)
	PipeAndClose(conn, lconn)
}

func (cc *Client) handleDynamicForward(conn net.Conn) {
	addr, err := getOriginDst(conn)
	if err == nil {
		if addr.String() != conn.LocalAddr().String() {
			// transparent proxy
			// iptables redirect the packet to this port
			cc.handleTransparentProxy(conn, addr)
			return
		}
	} else {
		// SO_ORIGNAL_DST failed
		// just ignore it
		Log(DEBUG, "get original destination on %s failed: %s, ignore",
			conn.LocalAddr(), err)
	}

	// socks5 to this port
	s := socks.Conn{Conn: conn, Dial: cc.client.Dial}
	s.Serve()
}

func (cc *Client) handleTransparentProxy(c net.Conn, addr net.Addr) {
	c2, err := cc.client.Dial("tcp", addr.String())
	if err != nil {
		Log(ERROR, "%s", err)
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
			_, _, err := cc.sshConn.SendRequest("keepalive@openssh.org", true, nil)
			if err != nil {
				Log(DEBUG, "keep alive error: %s", err.Error())
				count++
			} else {
				count = 0
			}
			if count >= maxCount {
				Log(ERROR, "keep alive hit max count, exit")
				cc.sshConn.Close()
				// send exit signal
				select {
				case cc.ch <- 1:
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
		Log(ERROR, "signal %d received, exit", s1)
		select {
		case cc.ch <- 1:
		default:
		}
	}
}
