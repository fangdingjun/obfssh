package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fangdingjun/go-log/v5"
	"github.com/fangdingjun/obfssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var dialer = &net.Dialer{Timeout: 15 * time.Second}

func main() {
	var configfile string
	var cfg config
	var logfile string
	var logFileCount int
	var logFileSize int64
	var loglevel string

	flag.StringVar(&configfile, "f", "", "configure file")
	flag.StringVar(&cfg.Username, "l", os.Getenv("USER"), "ssh username")
	flag.StringVar(&cfg.Password, "pw", "", "ssh password")
	flag.IntVar(&cfg.Port, "p", 22, "remote port")
	flag.StringVar(&cfg.PrivateKey, "i", "", "private key file")
	flag.BoolVar(&cfg.TLS, "tls", false, "use tls or not")
	flag.BoolVar(&cfg.TLSInsecure, "tls-insecure", false, "insecure tls connnection")
	flag.Var(&cfg.LocalForwards, "L", "forward local port to remote, format [local_host:]local_port:remote_host:remote_port")
	flag.Var(&cfg.RemoteForwards, "R", "forward remote port to local, format [remote_host:]remote_port:local_host:local_port")
	flag.BoolVar(&cfg.NotRunCmd, "N", false, "not run remote command, useful when do port forward")
	flag.Var(&cfg.DynamicForwards, "D", "enable dynamic forward, format [local_host:]local_port")
	flag.BoolVar(&cfg.Debug, "d", false, "verbose mode")
	flag.IntVar(&cfg.KeepaliveInterval, "keepalive_interval", 10, "keep alive interval")
	flag.IntVar(&cfg.KeepaliveMax, "keepalive_max", 5, "keep alive max")
	flag.Var(&cfg.DynamicHTTP, "http", "listen for http port")
	flag.StringVar(&logfile, "log_file", "", "log file, default stdout")
	flag.IntVar(&logFileCount, "log_count", 10, "max count of log to keep")
	flag.Int64Var(&logFileSize, "log_size", 10, "max log file size MB")
	flag.StringVar(&loglevel, "log_level", "INFO", "log level, values:\nOFF, FATAL, PANIC, ERROR, WARN, INFO, DEBUG")

	flag.Usage = usage

	flag.Parse()

	if logfile != "" {
		log.Default.Out = &log.FixedSizeFileWriter{
			MaxCount: logFileCount,
			Name:     logfile,
			MaxSize:  logFileSize * 1024 * 1024,
		}
	}

	if cfg.Debug {
		loglevel = "DEBUG"
	}

	if loglevel != "" {
		lv, err := log.ParseLevel(loglevel)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		log.Default.Level = lv
	}

	if configfile != "" {
		if err := loadConfig(&cfg, configfile); err != nil {
			log.Fatal(err)
		}
	}

	log.Debugf("obfssh client start")

	auth := []ssh.AuthMethod{}

	var agentConn net.Conn
	var err error
	var agentClient agent.ExtendedAgent

	// read ssh agent and default auth key
	if cfg.Password == "" && cfg.PrivateKey == "" {
		var pkeys []ssh.Signer

		// read default ssh private
		home := os.Getenv("HOME")
		for _, f := range []string{
			".ssh/id_rsa",
			".ssh/id_dsa",
			".ssh/identity",
			".ssh/id_ecdsa",
			".ssh/id_ed25519",
		} {
			k1 := filepath.Join(home, f)
			if pemBytes, err := ioutil.ReadFile(k1); err == nil {
				if priKey, err := ssh.ParsePrivateKey(pemBytes); err == nil {
					log.Debugf("add private key: %s", k1)
					//auth = append(auth, ssh.PublicKeys(priKey))
					pkeys = append(pkeys, priKey)
				}
			}
		}

		// auth with agent
		agentConn, err = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err == nil {
			defer agentConn.Close()
			log.Debugf("add auth method with agent %s", os.Getenv("SSH_AUTH_SOCK"))
			agentClient = agent.NewClient(agentConn)
			//auth = append(auth, ssh.PublicKeysCallback(agentClient.Signers))
			signers, err := agentClient.Signers()
			if err == nil {
				pkeys = append(pkeys, signers...)
			} else {
				log.Debugf("get key from agent failed: %s", err)
			}
		} else {
			log.Debugf("connect to agent failed")
		}

		if len(pkeys) != 0 {
			log.Debugf("private key length %d", len(pkeys))
			auth = append(auth, ssh.PublicKeys(pkeys...))
		}

	}

	args := flag.Args()
	var cmd string
	host := cfg.Host
	if host == "" {
		switch len(args) {
		case 0:
			fmt.Println("you must specify the remote host")
			usage()
		case 1:
			host = args[0]
			cmd = ""
		default:
			host = args[0]
			cmd = strings.Join(args[1:], " ")
		}
	} else {
		cmd = strings.Join(args, " ")
	}

	if strings.Contains(host, "@") {
		ss := strings.SplitN(host, "@", 2)
		cfg.Username = ss[0]
		host = ss[1]
	}

	// process user specified private key
	if cfg.PrivateKey != "" {
		pemBytes, err := ioutil.ReadFile(cfg.PrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		priKey, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			log.Fatal(err)
		}
		log.Debugf("add private key %s", cfg.PrivateKey)
		auth = append(auth, ssh.PublicKeys(priKey))
	}

	if cfg.Password != "" {
		log.Debugf("add password auth method")
		auth = append(auth, ssh.Password(cfg.Password))
	} else {
		log.Debugf("add keyboard interactive auth")
		//auth = append(auth,
		//		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(keyboardAuth), 3))
		auth = append(auth,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordAuth), 3))
	}

	config := &ssh.ClientConfig{
		User:    cfg.Username,
		Auth:    auth,
		Timeout: 10 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr,
			key ssh.PublicKey) error {
			log.Debugf("%s %s %+v", hostname, remote, key)
			return nil
		},
	}

	// parse environment proxy
	updateProxyFromEnv(&cfg)

	var c net.Conn
	var rhost string

	if strings.HasPrefix(host, "ws://") || strings.HasPrefix(host, "wss://") {
		c, err = obfssh.NewWSConn(host)
		u, _ := url.Parse(host)
		rhost = u.Host
	} else {
		rhost = net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Port))
		if cfg.Proxy.Scheme != "" && cfg.Proxy.Host != "" && cfg.Proxy.Port != 0 {
			switch cfg.Proxy.Scheme {
			case "http":
				log.Debugf("use http proxy %s:%d to connect to server",
					cfg.Proxy.Host, cfg.Proxy.Port)
				c, err = dialHTTPProxy(host, cfg.Port, cfg.Proxy)
			case "https":
				log.Debugf("use https proxy %s:%d to connect to server",
					cfg.Proxy.Host, cfg.Proxy.Port)
				c, err = dialHTTPSProxy(host, cfg.Port, cfg.Proxy)
			case "socks5":
				log.Debugf("use socks proxy %s:%d to connect to server",
					cfg.Proxy.Host, cfg.Proxy.Port)
				c, err = dialSocks5Proxy(host, cfg.Port, cfg.Proxy)
			default:
				err = fmt.Errorf("unsupported scheme: %s", cfg.Proxy.Scheme)
			}
		} else {
			log.Debugf("dail to %s", rhost)
			c, err = dialer.Dial("tcp", rhost)
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("dail success")

	timeout := time.Duration(cfg.KeepaliveInterval*2) * time.Second

	var _conn = c

	conn := &obfssh.TimedOutConn{Conn: c, Timeout: timeout}

	if cfg.TLS {
		log.Debugf("begin tls handshake")
		_conn = tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.TLSInsecure,
		})
		if err := _conn.(*tls.Conn).Handshake(); err != nil {
			log.Fatal(err)
		}
		log.Debugf("tls handshake done")
	}

	conf := &obfssh.Conf{
		Timeout:           timeout,
		KeepAliveInterval: time.Duration(cfg.KeepaliveInterval) * time.Second,
		KeepAliveMax:      cfg.KeepaliveMax,
	}

	log.Debugf("ssh negotation")
	client, err := obfssh.NewClient(_conn, config, rhost, conf)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("ssh negotation success")

	if agentClient != nil {
		client.SetAuthAgent(agentClient)
	}

	var local, remote string

	// process port forward

	for _, p := range cfg.LocalForwards {
		addr := parseForwardAddr(p)
		if len(addr) != 4 && len(addr) != 3 {
			log.Errorf("wrong forward addr %s, format: [local_host:]local_port:remote_host:remote_port", p)
			continue
		}
		if len(addr) == 4 {
			local = strings.Join(addr[:2], ":")
			remote = strings.Join(addr[2:], ":")
		} else {
			local = fmt.Sprintf(":%s", addr[0])
			remote = strings.Join(addr[1:], ":")
		}
		//log.Printf("add local to remote %s->%s", local, remote)
		if err := client.AddLocalForward(local, remote); err != nil {
			log.Errorln(err)
		}
	}

	for _, p := range cfg.RemoteForwards {
		addr := parseForwardAddr(p)
		if len(addr) != 4 && len(addr) != 3 {
			log.Errorf("wrong forward addr %s, format: [local_host:]local_port:remote_host:remote_port", p)
			continue
		}
		if len(addr) == 4 {
			remote = strings.Join(addr[:2], ":")
			local = strings.Join(addr[2:], ":")
		} else {
			remote = fmt.Sprintf("0.0.0.0:%s", addr[0])
			local = strings.Join(addr[1:], ":")
		}
		//log.Printf("add remote to local %s->%s", remote, local)
		if err := client.AddRemoteForward(local, remote); err != nil {
			log.Errorln(err)
		}
	}
	for _, p := range cfg.DynamicForwards {

		if strings.Index(p, ":") == -1 {
			local = fmt.Sprintf(":%s", p)
		} else {
			local = p
		}
		//log.Printf("listen on %s", local)
		if err := client.AddDynamicForward(local); err != nil {
			log.Errorln(err)
		}
	}

	for _, p := range cfg.DynamicHTTP {
		if strings.Index(p, ":") == -1 {
			local = fmt.Sprintf(":%s", p)
		} else {
			local = p
		}
		//log.Printf("listen on %s", local)
		if err := client.AddDynamicHTTPForward(local); err != nil {
			log.Errorln(err)
		}

	}

	hasErr := false

	if !cfg.NotRunCmd {
		if cmd != "" {
			if err := client.RunCmd(cmd); err != nil {
				log.Errorln(err)
				hasErr = true
			}
		} else {
			if err := client.Shell(); err != nil {
				hasErr = true
				log.Errorln(err)
			}
		}
	}

	if err := client.Run(); err != nil {
		log.Errorln(err)
		hasErr = true
	}

	log.Debugf("obfssh client exit")
	if hasErr {
		os.Exit(1)
	}
}

func parseForwardAddr(s string) []string {
	ss := strings.FieldsFunc(s, func(c rune) bool {
		if c == ':' {
			return true
		}
		return false
	})
	return ss
}

/*
func keyboardAuth(user, instruction string, question []string, echos []bool) (answers []string, err error) {
	if len(question) == 0 {
		fmt.Printf("%s %s\n", user, instruction)
		return nil, nil
	}
	r := bufio.NewReader(os.Stdin)
	var s string
	for i := range question {
		fmt.Printf("%s ", question[i])
		s, err = r.ReadString('\n')
		answers = append(answers, s)
	}
	return
}
*/

func passwordAuth() (string, error) {
	// read password from console
	fmt.Fprintf(os.Stdout, "Password: ")
	s, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stdout, "\n")
	return strings.Trim(string(s), " \r\n"), err
}

func usage() {
	usageStr := `Usage:
  obfssh -N -d -D [bind_address:]port -f configfile
   -tls -tls-insecure -log_file /path/to/file
   -log_count 10 -log_size 10
   -log_level INFO
   -i identity_file -L [bind_address:]port:host:hostport
   -l login_name -pw password -p port 
   -http [bind_addr:]port
   -R [bind_address:]port:host:hostport [user@]hostname [command]

Options:
    -d verbose mode

    -D [bind_adress:]port
      Specifies a local dynamic application-level port
      forwarding. This listen a port on the local side
      and act as socks server, when a connection is made
      to this port, the connection is forwarded over 
      the secure channel, the distination is determined
      by socks protocol.
      This option can be specified multiple times.

    -f configfile
      Specifies a config file to load arguments.
      The config file is YAML format,
      see config_example.yaml for details.

    -i identity_file
      Specifies a identity(private key) for public key authentication.

    -L [bind_address:]port:host:hostport
      Listen a port on local side, when a connection is made to
      this port, the connection is forwared over the secure 
      channel to host:portport from the remote machine.
      This option can be specified multiple times.

    -l login_name
      specifies the user to log in as on the remote machine.
    
    -N  Do not execute commannd or start shell on remote machine.
      This is useful for just port forwarding.

    -p port
      Port to connect to on the remote host
    
    -pw password
      Specifies the password for log in remote machine

    -R [bind_address:]port:host:hostport
      Listen a port on remote machine, when a connection is 
      made to that port, the connection is forwarded over
      the secure channel to host:hostport from the local machine.
      This option can be specified multiple times.

    -keepalive_interval interval
      Specifies the interval of keep alive message,
      the interval is integer in seconds.

    -keepalive_max max
      Specifies the max error count for keep alive,
      when the count reach the max, the connection will
      be abort.

    -http [bind_addr:]port
       listen a port and act as http proxy server, 
       but connect to target server through
       encrypt ssh connection
       similar like -D, but input is http, not socks5

    -tls
       connect to server via TLS

    -tls-insecure
       do not verify server's tls ceritificate
       
    -log_file
       log file, default stdout
    
    -log_count
      max count of log file to keep, default 10

    -log_size
       max log size MB, default 10

    -log_level
       log level, values:
          OFF, FATAL, PANIC, ERROR, WARN, INFO, DEBUG
`
	fmt.Printf("%s", usageStr)
	os.Exit(1)
}
