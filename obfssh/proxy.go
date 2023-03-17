package main

import (
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/fangdingjun/go-log/v5"
)

func updateProxyFromEnv(cfg *config) {
	if cfg.Proxy.Scheme != "" && cfg.Proxy.Host != "" && cfg.Proxy.Port != 0 {
		log.Debugf("proxy already specified by config, not parse environment proxy")
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
		log.Debugf("parse proxy from environment failed: %s", err)
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
