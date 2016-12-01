package main

import (
	//"bytes"
	"flag"
	"fmt"
	"github.com/fangdingjun/obfssh"
	"github.com/golang/crypto/ssh"
	"github.com/golang/crypto/ssh/agent"
	//"github.com/golang/crypto/ssh/terminal"
	"time"
	//"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	//"os/signal"
	"path/filepath"
	"strings"
	//"sync"
	//"syscall"
)

var method, encryptKey string

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

var localForwards stringSlice
var remoteForwards stringSlice
var dynamicForwards stringSlice

func main() {
	var host, port, user, pass, key string
	//var localForward, remoteForward, dynamicForward string
	var notRunCmd bool
	var debug bool

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
	flag.Parse()

	if debug {
		obfssh.SSHLogLevel = obfssh.DEBUG
	}
	auth := []ssh.AuthMethod{}

	// read ssh agent and default auth key
	if pass == "" && key == "" {
		if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			obfssh.Log(obfssh.DEBUG, "add auth method with agent %s", os.Getenv("SSH_AUTH_SOCK"))
			auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
		}

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
					auth = append(auth, ssh.PublicKeys(priKey))
				}
			}
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

	if pass != "" {
		obfssh.Log(obfssh.DEBUG, "add password auth method")
		auth = append(auth, ssh.Password(pass))
	}

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

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 10 * time.Second,
	}

	h := net.JoinHostPort(host, port)
	c, err := net.Dial("tcp", h)
	if err != nil {
		log.Fatal(err)
	}

	client, err := obfssh.NewClient(c, config, h, method, encryptKey)
	if err != nil {
		log.Fatal(err)
	}
	var local, remote string
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
