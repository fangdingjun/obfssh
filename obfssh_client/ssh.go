package main

import (
	"flag"
	"fmt"
	"github.com/bgentry/speakeasy"
	"github.com/fangdingjun/obfssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var configfile string
	var cfg config

	flag.StringVar(&configfile, "f", "", "configure file")
	flag.StringVar(&cfg.Username, "l", os.Getenv("USER"), "ssh username")
	flag.StringVar(&cfg.Password, "pw", "", "ssh password")
	flag.IntVar(&cfg.Port, "p", 22, "remote port")
	flag.StringVar(&cfg.PrivateKey, "i", "", "private key file")
	flag.Var(&cfg.LocalForwards, "L", "forward local port to remote, format [local_host:]local_port:remote_host:remote_port")
	flag.Var(&cfg.RemoteForwards, "R", "forward remote port to local, format [remote_host:]remote_port:local_host:local_port")
	flag.BoolVar(&cfg.NotRunCmd, "N", false, "not run remote command, useful when do port forward")
	flag.Var(&cfg.DynamicForwards, "D", "enable dynamic forward, format [local_host:]local_port")
	flag.StringVar(&cfg.ObfsMethod, "obfs_method", "", "transport encrypt method, avaliable: rc4, aes, empty means disable encrypt")
	flag.StringVar(&cfg.ObfsKey, "obfs_key", "", "transport encrypt key")
	flag.BoolVar(&cfg.Debug, "d", false, "verbose mode")
	flag.IntVar(&cfg.KeepaliveInterval, "keepalive_interval", 10, "keep alive interval")
	flag.IntVar(&cfg.KeepaliveMax, "keepalive_max", 5, "keep alive max")
	flag.BoolVar(&cfg.DisableObfsAfterHandshake, "disable_obfs_after_handshake", false, "disable obfs after handshake")
	flag.Usage = usage
	flag.Parse()

	if configfile != "" {
		if err := loadConfig(&cfg, configfile); err == nil {
			log.Fatal(err)
		}
	}

	if cfg.Debug {
		obfssh.SSHLogLevel = obfssh.DEBUG
	}

	auth := []ssh.AuthMethod{}

	var agentConn net.Conn
	var err error

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
					obfssh.Log(obfssh.DEBUG, "add private key: %s", k1)
					//auth = append(auth, ssh.PublicKeys(priKey))
					pkeys = append(pkeys, priKey)
				}
			}
		}

		// auth with agent
		agentConn, err = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err == nil {
			defer agentConn.Close()
			obfssh.Log(obfssh.DEBUG, "add auth method with agent %s", os.Getenv("SSH_AUTH_SOCK"))
			agentClient := agent.NewClient(agentConn)
			//auth = append(auth, ssh.PublicKeysCallback(agentClient.Signers))
			signers, err := agentClient.Signers()
			if err == nil {
				pkeys = append(pkeys, signers...)
			} else {
				obfssh.Log(obfssh.DEBUG, "get key from agent failed: %s", err)
			}
		} else {
			obfssh.Log(obfssh.DEBUG, "connect to agent failed")
		}

		if len(pkeys) != 0 {
			obfssh.Log(obfssh.DEBUG, "private key length %d", len(pkeys))
			auth = append(auth, ssh.PublicKeys(pkeys...))
		}

	}

	args := flag.Args()
	var cmd string
	host := cfg.Host
	if host == "" {
		switch len(args) {
		case 0:
			flag.PrintDefaults()
			log.Fatal("you must specify the remote host")
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
		obfssh.Log(obfssh.DEBUG, "add private key %s", cfg.PrivateKey)
		auth = append(auth, ssh.PublicKeys(priKey))
	}

	if cfg.Password != "" {
		obfssh.Log(obfssh.DEBUG, "add password auth method")
		auth = append(auth, ssh.Password(cfg.Password))
	} else {
		obfssh.Log(obfssh.DEBUG, "add keyboard interactive auth")
		//auth = append(auth,
		//		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(keyboardAuth), 3))
		auth = append(auth,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordAuth), 3))
	}

	config := &ssh.ClientConfig{
		User:    cfg.Username,
		Auth:    auth,
		Timeout: 10 * time.Second,
	}

	rhost := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Port))

	c, err := net.Dial("tcp", rhost)
	if err != nil {
		log.Fatal(err)
	}

	conf := &obfssh.Conf{
		ObfsMethod:                cfg.ObfsMethod,
		ObfsKey:                   cfg.ObfsKey,
		Timeout:                   time.Duration(cfg.KeepaliveInterval+5) * time.Second,
		KeepAliveInterval:         time.Duration(cfg.KeepaliveInterval) * time.Second,
		KeepAliveMax:              cfg.KeepaliveMax,
		DisableObfsAfterHandshake: cfg.DisableObfsAfterHandshake,
	}

	client, err := obfssh.NewClient(c, config, rhost, conf)
	if err != nil {
		log.Fatal(err)
	}

	var local, remote string

	// process port forward

	for _, p := range cfg.LocalForwards {
		addr := parseForwardAddr(p)
		if len(addr) != 4 && len(addr) != 3 {
			log.Printf("wrong forward addr %s, format: [local_host:]local_port:remote_host:remote_port", p)
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
			log.Println(err)
		}
	}

	for _, p := range cfg.RemoteForwards {
		addr := parseForwardAddr(p)
		if len(addr) != 4 && len(addr) != 3 {
			log.Printf("wrong forward addr %s, format: [local_host:]local_port:remote_host:remote_port", p)
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
			log.Println(err)
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
			log.Println(err)
		}
	}

	if !cfg.NotRunCmd {
		if cmd != "" {
			if d, err := client.RunCmd(cmd); err != nil {
				log.Println(err)
			} else {
				//log.Printf("%s", string(d))
				fmt.Printf("%s", string(d))
			}
		} else {
			if err := client.Shell(); err != nil {
				log.Println(err)
			}
		}
	}
	client.Run()
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
	s, err := speakeasy.Ask("Password: ")
	return strings.Trim(s, " \r\n"), err
}

func usage() {
	usageStr := `Usage:
  obfss_client -N -d -D [bind_address:]port -f configfile
   -i identity_file -L [bind_address:]port:host:hostport -l login_name
   -pw password -p port 
   -R [bind_address:]port:host:hostport [user@]hostname [command]

Options:

	-d  verbose mode

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
`
	fmt.Printf("%s", usageStr)
	os.Exit(1)
}
