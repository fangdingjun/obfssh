package obfssh

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/fangdingjun/go-log/v5"
	socks "github.com/fangdingjun/socks-go"
)

type httpProxyConn struct {
	c net.Conn
	r io.Reader
}

func (hc *httpProxyConn) Read(b []byte) (int, error) {
	return hc.r.Read(b)
}

func (hc *httpProxyConn) Write(b []byte) (int, error) {
	return hc.c.Write(b)
}

func (hc *httpProxyConn) Close() error {
	return hc.c.Close()
}
func (hc *httpProxyConn) LocalAddr() net.Addr {
	return hc.c.LocalAddr()
}

func (hc *httpProxyConn) RemoteAddr() net.Addr {
	return hc.c.RemoteAddr()
}

func (hc *httpProxyConn) SetDeadline(t time.Time) error {
	return hc.c.SetDeadline(t)
}

func (hc *httpProxyConn) SetReadDeadline(t time.Time) error {
	return hc.c.SetReadDeadline(t)
}

func (hc *httpProxyConn) SetWriteDeadline(t time.Time) error {
	return hc.c.SetWriteDeadline(t)
}

// validate the interface implements
var _ net.Conn = &httpProxyConn{}

func httpProxyHandshake(c net.Conn, addr string) (net.Conn, error) {
	log.Debugf("http handshake with %s", addr)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n", addr)
	fmt.Fprintf(c, "Host: %s\r\n", addr)
	fmt.Fprintf(c, "User-Agent: go/1.7\r\n")
	fmt.Fprintf(c, "\r\n")

	r := bufio.NewReader(c)
	tp := textproto.NewReader(r)

	// read status line
	statusLine, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}

	if statusLine[0:4] != "HTTP" {
		return nil, fmt.Errorf("not http reply")
	}

	status := strings.Fields(statusLine)[1]

	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, err
	}

	if statusCode != 200 {
		return nil, fmt.Errorf("http status error %d", statusCode)
	}

	// read header
	if _, err = tp.ReadMIMEHeader(); err != nil {
		return nil, err
	}

	return &httpProxyConn{c: c, r: r}, nil
}

func dialHTTPProxy(addr string, p *url.URL) (net.Conn, error) {
	log.Debugf("dial to %s", p.Host)
	c, err := dialer.Dial("tcp", p.Host)
	if err != nil {
		return nil, err
	}

	c1, err := httpProxyHandshake(c, addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	return c1, nil
}

func dialHTTPSProxy(addr string, p *url.URL) (net.Conn, error) {
	hostname := p.Host

	tlsconfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	c, err := tls.DialWithDialer(dialer, "tcp", p.Host, tlsconfig)
	if err != nil {
		return nil, err
	}

	if err := c.Handshake(); err != nil {
		c.Close()
		return nil, err
	}

	c1, err := httpProxyHandshake(c, addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	return c1, nil
}

func dialSocks5Proxy(addr string, p *url.URL) (net.Conn, error) {
	c, err := dialer.Dial("tcp", p.Host)
	if err != nil {
		return nil, err
	}

	c1 := &socks.Client{Conn: c}
	c2, err := c1.Dial("tcp", addr)
	if err != nil {
		c1.Close()
		return nil, err
	}
	return c2, err
}
