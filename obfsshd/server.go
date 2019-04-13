package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/fangdingjun/go-log"
	"github.com/fangdingjun/obfssh"
	"golang.org/x/crypto/ssh"
)

func main() {

	var configfile string
	var logfile string
	var logFileCount int
	var logFileSize int64
	var loglevel string

	flag.StringVar(&configfile, "c", "config.yaml", "configure file")
	flag.StringVar(&logfile, "log_file", "", "log file, default stdout")
	flag.IntVar(&logFileCount, "log_count", 10, "max count of log to keep")
	flag.Int64Var(&logFileSize, "log_size", 10, "max log file size MB")
	flag.StringVar(&loglevel, "log_level", "INFO", "log level, values:\nOFF, FATAL, PANIC, ERROR, WARN, INFO, DEBUG")

	flag.Parse()

	if logfile != "" {
		log.Default.Out = &log.FixedSizeFileWriter{
			MaxCount: logFileCount,
			Name:     logfile,
			MaxSize:  logFileSize * 1024 * 1024,
		}
	}

	if loglevel != "" {
		lv, err := log.ParseLevel(loglevel)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		log.Default.Level = lv
	}

	conf, err := loadConfig(configfile)
	if err != nil {
		log.Fatal(err)
	}

	sconf := &obfssh.Conf{}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if u, err := conf.getUser(c.User()); err == nil {
				if u.Password != "" && c.User() == u.Username && string(pass) == u.Password {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("password reject for user %s", c.User())
		},

		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			checker := &ssh.CertChecker{
				IsUserAuthority: func(k ssh.PublicKey) bool {
					if u, err := conf.getUser(c.User()); err == nil {
						for _, pk := range u.publicKeys {
							if k.Type() == pk.Type() &&
								bytes.Compare(k.Marshal(), pk.Marshal()) == 0 {
								return true
							}
						}
					}
					return false
				},
			}
			checker.UserKeyFallback = func(c1 ssh.ConnMetadata, k1 ssh.PublicKey) (*ssh.Permissions, error) {
				log.Debug("user key fallback")
				if checker.IsUserAuthority(k1) {
					return nil, nil
				}
				return nil, errors.New("public not acceptable")
			}
			return checker.Authenticate(c, k)
		},

		// auth log
		AuthLogCallback: func(c ssh.ConnMetadata, method string, err error) {
			if err != nil {
				log.Debugf("%s", err.Error())
				log.Debugf("%s auth failed for %s from %s", method, c.User(), c.RemoteAddr())
			} else {
				log.Debugf("Accepted %s for user %s from %s", method, c.User(), c.RemoteAddr())
			}
		},
	}

	privateBytes, err := ioutil.ReadFile(conf.HostKey)
	if err != nil {
		log.Fatal(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal(err)
	}

	config.AddHostKey(private)
	for _, lst := range conf.Listen {
		go func(lst listen) {
			var l net.Listener
			var err error

			l, err = net.Listen("tcp", fmt.Sprintf(":%d", lst.Port))
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()

			if lst.Key != "" && lst.Cert != "" {
				cert, err := tls.LoadX509KeyPair(lst.Cert, lst.Key)
				if err != nil {
					log.Fatal(err)
				}
				l = tls.NewListener(&protoListener{l}, &tls.Config{
					Certificates: []tls.Certificate{cert},
				})
			}

			for {
				c, err := l.Accept()
				if err != nil {
					fmt.Println(err)
					return
				}

				log.Debugf("accept tcp connection from %s", c.RemoteAddr())

				go func(c net.Conn) {
					defer c.Close()
					sc, err := obfssh.NewServer(c, config, sconf)
					if err != nil {
						c.Close()
						log.Errorf("%s", err.Error())
						return
					}
					sc.Run()
				}(c)
			}
		}(lst)
	}

	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-ch:
		log.Printf("received signal %s, exit.", s)
	}

}
