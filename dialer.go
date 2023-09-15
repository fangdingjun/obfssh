package obfssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	log "github.com/fangdingjun/go-log/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dial is used.
	NetDial func(network, addr string) (net.Conn, error)

	Proxy func() (*url.URL, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// If either NetDialTLS or NetDialTLSContext are set, Dial assumes the TLS handshake
	// is done there and TLSClientConfig is ignored.
	TLSClientConfig *tls.Config

	NetConf *Conf
}

func (d *Dialer) Dial(addr string, conf *ssh.ClientConfig) (*Client, error) {
	if d.NetConf.Timeout == 0 {
		d.NetConf.Timeout = 15 * time.Second
	}
	if d.NetConf.KeepAliveInterval == 0 {
		d.NetConf.KeepAliveInterval = 10
	}
	if d.NetConf.KeepAliveMax == 0 {
		d.NetConf.KeepAliveMax = 3
	}
	var dialFunc func(network, addr string) (net.Conn, error)
	if d.NetDial == nil {
		dialFunc = dialer.Dial
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if d.Proxy != nil {
		dialFunc = func(network, addr string) (net.Conn, error) {
			var conn net.Conn
			var err error
			u1, _ := d.Proxy()
			if u1 == nil {
				return dialer.Dial(network, addr)
			}
			log.Debugf("connect to proxy %s", u1.String())
			switch u1.Scheme {
			case "http":
				conn, err = dialHTTPProxy(addr, u1)
			case "https":
				conn, err = dialHTTPSProxy(addr, u1)
			case "socks5":
				conn, err = dialSocks5Proxy(addr, u1)
			default:
				return nil, fmt.Errorf("unknown proxy scheme %s", u1.Scheme)
			}
			if err != nil {
				log.Errorf("connect to proxy error %s", err)
			}
			return conn, err
		}
	}

	switch u.Scheme {
	case "":
		conn, err := dialFunc("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		return NewClient(&TimedOutConn{Conn: conn, Timeout: d.NetConf.Timeout}, conf, u.Host, d.NetConf)
	case "tls":
		conn, err := dialFunc("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		conn = tls.Client(&TimedOutConn{Conn: conn, Timeout: d.NetConf.Timeout}, d.TLSClientConfig)
		return NewClient(conn, conf, u.Host, d.NetConf)
	case "ws":
		fallthrough
	case "wss":
		_addr := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		_dailer := websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				c, err := dialFunc(network, addr)
				return &TimedOutConn{Conn: c, Timeout: d.NetConf.Timeout}, err
			},
			TLSClientConfig: d.TLSClientConfig,
		}
		wsconn, res, err := _dailer.Dial(_addr, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusSwitchingProtocols {
			return nil, fmt.Errorf("websocket connect failed, http code %d", res.StatusCode)
		}
		_conn := &wsConn{Conn: wsconn}
		return NewClient(_conn, conf, u.Host, d.NetConf)
	default:
		return nil, fmt.Errorf("unknow scheme %s", u.Scheme)
	}
}

func (d *Dialer) DialContext(ctx context.Context, addr string, conf *ssh.ClientConfig) (*Client, error) {
	return nil, nil
}
