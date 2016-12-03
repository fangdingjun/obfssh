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

type stringSlice []string

func (lf *stringSlice) Set(val string) error {
	*lf = append(*lf, val)
	return nil
}

func (lf *stringSlice) String() string {
	s := ""
	if lf == nil {
		return s
	}
	for _, v := range *lf {
		s += " "
		s += v
	}
	return s
}

func main() {
	var host, port, user, pass, key string
	var method, encryptKey string
	var notRunCmd bool
	var debug bool
	var disableObfsAfterHandshake bool
	var keepAliveInterval, keepAliveMax int

	var localForwards stringSlice
	var remoteForwards stringSlice
	var dynamicForwards stringSlice

	flag.StringVar(&user, "l", os.Getenv("USER"), "ssh username")
	flag.StringVar(&pass, "pw", "", "ssh password")
	flag.StringVar(&port, "p", "22", "remote port")
	flag.StringVar(&key, "i", "", "private key file")
	flag.Var(&localForwards, "L", "forward local port to remote, format [local_host:]local_port:remote_host:remote_port")
	flag.Var(&remoteForwards, "R", "forward remote port to local, format [remote_host:]remote_port:local_host:local_port")
	flag.BoolVar(&notRunCmd, "N", false, "not run remote command, useful when do port forward")
	flag.Var(&dynamicForwards, "D", "enable dynamic forward, format [local_host:]local_port")
	flag.StringVar(&method, "obfs_method", "", "transport encrypt method, avaliable: rc4, aes, empty means disable encrypt")
	flag.StringVar(&encryptKey, "obfs_key", "", "transport encrypt key")
	flag.BoolVar(&debug, "d", false, "verbose mode")
	flag.IntVar(&keepAliveInterval, "keepalive_interval", 10, "keep alive interval")
	flag.IntVar(&keepAliveMax, "keepalive_max", 5, "keep alive max")
	flag.BoolVar(&disableObfsAfterHandshake, "disable_obfs_after_handshake", false, "disable obfs after handshake")
	flag.Parse()

	if debug {
		obfssh.SSHLogLevel = obfssh.DEBUG
	}

	auth := []ssh.AuthMethod{}

	var agentConn net.Conn
	var err error

	// read ssh agent and default auth key
	if pass == "" && key == "" {
		var pkeys []ssh.Signer

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

		if len(pkeys) != 0 {
			obfssh.Log(obfssh.DEBUG, "private key length %d", len(pkeys))
			auth = append(auth, ssh.PublicKeys(pkeys...))
		}

		agentConn, err = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err == nil {
			defer agentConn.Close()
			obfssh.Log(obfssh.DEBUG, "add auth method with agent %s", os.Getenv("SSH_AUTH_SOCK"))
			agentClient := agent.NewClient(agentConn)
			auth = append(auth, ssh.PublicKeysCallback(agentClient.Signers))
		} else {
			obfssh.Log(obfssh.DEBUG, "connect to agent failed")
		}
	}

	args := flag.Args()
	var cmd string
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

	if strings.Contains(host, "@") {
		ss := strings.SplitN(host, "@", 2)
		user = ss[0]
		host = ss[1]
	}

	// process user specified private key
	if key != "" {
		pemBytes, err := ioutil.ReadFile(key)
		if err != nil {
			log.Fatal(err)
		}
		priKey, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			log.Fatal(err)
		}
		obfssh.Log(obfssh.DEBUG, "add private key %s", key)
		auth = append(auth, ssh.PublicKeys(priKey))
	}

	if pass != "" {
		obfssh.Log(obfssh.DEBUG, "add password auth method")
		auth = append(auth, ssh.Password(pass))
	} else {
		obfssh.Log(obfssh.DEBUG, "add keyboard interactive auth")
		//auth = append(auth,
		//		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(keyboardAuth), 3))
		auth = append(auth,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordAuth), 3))
	}

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 10 * time.Second,
	}

	rhost := net.JoinHostPort(host, port)

	c, err := net.Dial("tcp", rhost)
	if err != nil {
		log.Fatal(err)
	}

	conf := &obfssh.Conf{
		ObfsMethod:                method,
		ObfsKey:                   encryptKey,
		Timeout:                   time.Duration(keepAliveInterval+5) * time.Second,
		KeepAliveInterval:         time.Duration(keepAliveInterval) * time.Second,
		KeepAliveMax:              keepAliveMax,
		DisableObfsAfterHandshake: disableObfsAfterHandshake,
	}

	client, err := obfssh.NewClient(c, config, rhost, conf)
	if err != nil {
		log.Fatal(err)
	}

	var local, remote string

	// process port forward

	for _, p := range localForwards {
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

	for _, p := range remoteForwards {
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
	for _, p := range dynamicForwards {

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

	if !notRunCmd {
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
