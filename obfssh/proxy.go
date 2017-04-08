package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/fangdingjun/obfssh"
	socks "github.com/fangdingjun/socks-go"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func updateProxyFromEnv(cfg *config) {
	if cfg.Proxy.Scheme != "" && cfg.Proxy.Host != "" && cfg.Proxy.Port != 0 {
		obfssh.Log(obfssh.DEBUG, "proxy already specified by config, not parse environment proxy")
		return
	}

	proxyStr := os.Getenv("https_proxy")
	if proxyStr == "" {
		proxyStr = os.Getenv("HTTPS_PROXY")
	}

	if proxyStr == "" {
		proxyStr = os.Getenv("http_proxy")
	}

	if proxyStr == "" {
		proxyStr = os.Getenv("HTTP_PROXY")
	}

	if proxyStr == "" {
		return
	}

	u, err := url.Parse(proxyStr)
	if err != nil {
		obfssh.Log(obfssh.DEBUG, "parse proxy from environment failed: %s", err)
		return
	}

	cfg.Proxy.Scheme = u.Scheme

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// failed, maybe no port specified
		cfg.Proxy.Host = u.Host
	} else {
		cfg.Proxy.Host = host
		p, err := strconv.Atoi(port)
		if err == nil {
			cfg.Proxy.Port = int(p)
		}
	}

	// no port, set default port
	if cfg.Proxy.Port == 0 {
		if cfg.Proxy.Scheme == "https" {
			cfg.Proxy.Port = 443
		} else {
			cfg.Proxy.Port = 8080
		}
	}
}

func httpProxyHandshake(c net.Conn, host string, port int) error {
	fmt.Fprintf(c, "CONNECT %s:%d HTTP/1.1\r\n", host, port)
	fmt.Fprintf(c, "Host: %s:%d\r\n", host, port)
	fmt.Fprintf(c, "User-Agent: go/1.7\r\n")
	fmt.Fprintf(c, "\r\n")

	r := bufio.NewReader(c)
	tp := textproto.NewReader(r)

	// read status line
	statusLine, err := tp.ReadLine()
	if err != nil {
		return err
	}

	if statusLine[0:4] != "HTTP" {
		return fmt.Errorf("not http reply")
	}

	status := strings.Fields(statusLine)[1]

	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return err
	}

	if statusCode != 200 {
		return fmt.Errorf("http status error %d", statusCode)
	}

	// read header
	if _, err = tp.ReadMIMEHeader(); err != nil {
		return err
	}

	return nil
}

func dialHTTPProxy(host string, port int, p proxy) (net.Conn, error) {
	c, err := net.Dial("tcp", net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port)))
	if err != nil {
		return nil, err
	}

	if err = httpProxyHandshake(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func dialHTTPSProxy(host string, port int, p proxy) (net.Conn, error) {
	hostname := p.Host
	if p.SNI != "" {
		hostname = p.SNI
	}

	tlsconfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: p.Insecure,
	}

	c, err := tls.Dial("tcp", net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port)), tlsconfig)
	if err != nil {
		return nil, err
	}

	if err := c.Handshake(); err != nil {
		c.Close()
		return nil, err
	}

	if err = httpProxyHandshake(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func dialSocks5Proxy(host string, port int, p proxy) (net.Conn, error) {
	c, err := net.Dial("tcp", net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port)))
	if err != nil {
		return nil, err
	}

	c1 := &socks.Client{Conn: c}
	c2, err := c1.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		c1.Close()
		return nil, err
	}
	return c2, err
}
