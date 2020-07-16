package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fangdingjun/go-log/v5"
	"github.com/fangdingjun/obfssh"
	"github.com/kr/fs"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type options struct {
	Debug       bool
	Port        int
	User        string
	Passwd      string
	TLS         bool
	TLSInsecure bool
	Recursive   bool
	PrivateKey  string
}

var dialer = &net.Dialer{Timeout: 10 * time.Second}

func main() {
	var cfg options
	var logfile string
	var logFileCount int
	var logFileSize int64
	var loglevel string

	flag.Usage = usage

	flag.BoolVar(&cfg.Debug, "d", false, "verbose mode")
	flag.IntVar(&cfg.Port, "p", 22, "port")
	flag.StringVar(&cfg.User, "l", os.Getenv("USER"), "user")
	flag.BoolVar(&cfg.TLS, "tls", false, "use tls or not")
	flag.BoolVar(&cfg.TLSInsecure, "tls-insecure", false, "insecure tls connection")
	flag.StringVar(&cfg.Passwd, "pw", "", "password")
	flag.StringVar(&cfg.PrivateKey, "i", "", "private key")
	flag.BoolVar(&cfg.Recursive, "r", false, "recursively copy entries")
	flag.StringVar(&logfile, "log_file", "", "log file, default stdout")
	flag.IntVar(&logFileCount, "log_count", 10, "max count of log to keep")
	flag.Int64Var(&logFileSize, "log_size", 10, "max log file size MB")
	flag.StringVar(&loglevel, "log_level", "INFO", "log level, values:\nOFF, FATAL, PANIC, ERROR, WARN, INFO, DEBUG")
	flag.Parse()

	args := flag.Args()

	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}
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

	var err error

	if strings.Contains(args[0], ":") {
		err = download(args, &cfg)
	} else {
		err = upload(args, &cfg)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func createSFTPConn(host, user string, cfg *options) (*sftp.Client, error) {
	auths := []ssh.AuthMethod{}

	// read ssh agent and default auth key
	if cfg.Passwd == "" && cfg.PrivateKey == "" {
		var pkeys []ssh.Signer
		if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			//auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
			if signers, err := agent.NewClient(aconn).Signers(); err == nil {
				log.Debugf("add private key from agent")
				pkeys = append(pkeys, signers...)
			} else {
				log.Debugf("get key from agent failed: %s", err)
			}
		} else {
			log.Debugf("dial to agent failed: %s", err)
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
					//auths = append(auths, ssh.PublicKeys(priKey))
					pkeys = append(pkeys, priKey)
					log.Debugf("add private key %s", k1)
				} else {
					log.Debugf("parse private key failed: %s", err)
				}
			}

		}

		if len(pkeys) != 0 {
			log.Debugf("totol %d private keys", len(pkeys))
			auths = append(auths, ssh.PublicKeys(pkeys...))
		}
	}

	if cfg.Passwd != "" {
		log.Debugf("add password auth")
		auths = append(auths, ssh.Password(cfg.Passwd))
	} else {
		log.Debugf("add keyboard interactive")
		auths = append(auths,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordAuth), 3))
	}

	if cfg.PrivateKey != "" {
		if buf, err := ioutil.ReadFile(cfg.PrivateKey); err == nil {
			if p, err := ssh.ParsePrivateKey(buf); err == nil {
				log.Debugf("add private key: %s", cfg.PrivateKey)
				auths = append(auths, ssh.PublicKeys(p))
			} else {
				log.Debugf("parse private key failed: %s", err)
			}
		} else {
			log.Debugf("read private key failed: %s", err)
		}
	}
	if user == "" {
		user = cfg.User
	}

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    auths,
		Timeout: 5 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	rhost := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Port))

	var c net.Conn
	var err error
	if cfg.TLS {
		c, err = tls.DialWithDialer(dialer, "tcp", rhost, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.TLSInsecure,
		})
	} else {
		c, err = dialer.Dial("tcp", rhost)
	}

	if err != nil {
		//log.Fatal(err)
		return nil, err
	}

	conf := &obfssh.Conf{
		Timeout:           10 * time.Second,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveMax:      5,
	}

	conn, err := obfssh.NewClient(c, config, rhost, conf)
	if err != nil {
		//log.Fatal(err)
		return nil, err
	}

	//defer conn.Close()

	sftpConn, err := sftp.NewClient(conn.Client(), sftp.MaxPacket(32*1024))
	if err != nil {
		//log.Fatal(err)
		return nil, err
	}
	return sftpConn, nil
}

func splitHostPath(s string) (string, string, string) {
	var user, host, path string
	r1 := s
	if strings.Contains(r1, "@") {
		ss1 := strings.SplitN(r1, "@", 2)
		user = ss1[0]
		r1 = ss1[1]
	}
	if strings.Contains(r1, ":") {
		ss2 := strings.SplitN(r1, ":", 2)
		host = ss2[0]
		path = ss2[1]
	} else {
		host = r1
	}
	return user, host, path
}

func download(args []string, cfg *options) error {

	var err1 error

	localFile := clean(args[len(args)-1])

	st, _ := os.Stat(localFile)

	if len(args) > 2 {
		if st != nil && !st.Mode().IsDir() {
			log.Fatal("can't transfer multiple files to file")
		}
		if st == nil {
			makeDirs(localFile, osDir{})
			if err := os.Mkdir(localFile, 0755); err != nil {
				log.Fatal(err)
			}
		}
		st, _ = os.Stat(localFile)
	}

	for _, f := range args[:len(args)-1] {
		user, host, path := splitHostPath(f)
		if host == "" || path == "" {
			return errors.New("invalid path")
		}

		path = clean(path)

		sftpConn, err := createSFTPConn(host, user, cfg)
		if err != nil {
			return err
		}

		st1, err := sftpConn.Stat(path)
		if err != nil {
			err1 = err
			log.Debugf("%s", err)
			sftpConn.Close()
			continue
		}
		if st1.Mode().IsDir() {
			if !cfg.Recursive {
				log.Debugf("omit remote directory %s", path)
				sftpConn.Close()
				continue
			}
			if err := rget(sftpConn, path, localFile); err != nil {
				log.Debugf("download error: %s", err)
				err1 = err
			}
			sftpConn.Close()
			continue
		}

		lfile := localFile
		if st != nil && st.Mode().IsDir() {
			lfile = filepath.Join(lfile, filepath.Base(path))
		}

		lfile = clean(lfile)

		if err := get(sftpConn, path, lfile); err != nil {
			log.Debugf("download error: %s", err)
			err1 = err
		}

		sftpConn.Close()
	}

	log.Debugf("done")
	return err1
}

func upload(args []string, cfg *options) error {

	rfile := args[len(args)-1]

	rfile = clean(rfile)

	user, host, path := splitHostPath(rfile)

	if host == "" || path == "" {
		return errors.New("invalid path")
	}

	path = clean(path)

	sftpConn, err := createSFTPConn(host, user, cfg)
	if err != nil {
		log.Debugf("create sftp failed: %s", err)
		return err
	}
	defer sftpConn.Close()

	st, _ := sftpConn.Stat(path)

	var err1 error
	if len(args) > 2 {
		if st != nil && !st.Mode().IsDir() {
			log.Fatal("multiple files can only been transferred to directory")
		}
		if st == nil {
			makeDirs(path, sftpConn)
			if err := sftpConn.Mkdir(path); err != nil {
				log.Fatal(err)
			}
		}
		st, _ = sftpConn.Stat(path)
	}

	for i := 0; i < len(args)-1; i++ {
		localFile := args[i]

		localFile = clean(localFile)

		st1, err := os.Stat(localFile)

		// local file not exists
		if err != nil {
			log.Debugf("%s", err)
			err1 = err
			continue
		}

		// directory
		if st1.Mode().IsDir() {
			if !cfg.Recursive {
				log.Debugf("omit directory %s", localFile)
				continue
			}
			// transfer directory
			if err := rput(sftpConn, localFile, path); err != nil {
				log.Debugf("%s", err)
				err1 = err
			}

			// next entry
			continue
		}

		// file

		remoteFile := path

		if st != nil && st.Mode().IsDir() {
			remoteFile = filepath.Join(path, filepath.Base(localFile))
		}

		remoteFile = clean(remoteFile)

		if err := put(sftpConn, localFile, remoteFile); err != nil {
			log.Debugf("upload %s failed: %s", localFile, err.Error())
			err1 = err
		}
	}
	return err1
}

func get(sftpConn *sftp.Client, remoteFile, localFile string) error {

	log.Debugf("download %s -> %s", remoteFile, localFile)

	fp, err := sftpConn.Open(remoteFile)
	if err != nil {
		return err
	}

	defer fp.Close()

	fp1, err := os.OpenFile(localFile, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	defer fp1.Close()

	//_, err = io.Copy(fp1, fp)
	err = copyFile(fp1, fp)
	if err != nil {
		return err
	}

	// set permission and modtime

	st, err := sftpConn.Stat(remoteFile)
	if err != nil {
		return err
	}

	if err := os.Chmod(localFile, st.Mode().Perm()); err != nil {
		return err
	}

	if err := os.Chtimes(localFile, st.ModTime(), st.ModTime()); err != nil {
		return err
	}

	log.Debugf("done")

	return nil
}

func put(sftpConn *sftp.Client, localFile, remoteFile string) error {
	log.Debugf("upload %s -> %s", localFile, remoteFile)

	fpw, err := sftpConn.OpenFile(remoteFile, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC)
	if err != nil {
		return err
	}

	defer fpw.Close()

	fpr, err := os.Open(localFile)
	if err != nil {
		return err
	}

	defer fpr.Close()

	//_, err = io.Copy(fpw, fpr)
	err = copyFile(fpw, fpr)
	if err != nil {
		return err
	}

	// set permission and modtime
	st, err := os.Stat(localFile)
	if err != nil {
		return err
	}

	if err := sftpConn.Chmod(remoteFile, st.Mode().Perm()); err != nil {
		return err
	}

	if err := sftpConn.Chtimes(remoteFile, st.ModTime(), st.ModTime()); err != nil {
		return err
	}

	log.Debugf("done")

	return nil
}

func rput(sftpConn *sftp.Client, localDir, remoteDir string) error {
	walker := fs.Walk(localDir)

	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		if st := walker.Stat(); !st.Mode().IsRegular() {
			log.Debugf("skip %s", walker.Path())
			continue
		}

		p := clean(walker.Path())

		p1 := strings.Replace(p, localDir, "", 1)

		fmt.Println(strings.TrimLeft(p1, "/"))

		p2 := clean(filepath.Join(remoteDir, p1))

		if err := makeDirs(p2, sftpConn); err != nil {
			return err
		}

		if err := put(sftpConn, p, p2); err != nil {
			return err
		}
	}
	return nil
}

func rget(sftpConn *sftp.Client, remoteDir, localDir string) error {
	log.Debugf("transfer recusive from remote to local, %s -> %s", remoteDir, localDir)

	walker := sftpConn.Walk(remoteDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		if st := walker.Stat(); !st.Mode().IsRegular() {
			log.Debugf("skip %s", walker.Path())
			continue
		}

		p := clean(walker.Path())
		p1 := strings.Replace(p, remoteDir, "", 1)
		p2 := clean(filepath.Join(localDir, p1))

		fmt.Println(strings.TrimLeft(p1, "/"))

		if err := makeDirs(p2, osDir{}); err != nil {
			return err
		}

		if err := get(sftpConn, p, p2); err != nil {
			return err
		}
	}

	return nil
}

type osDir struct{}

func (f osDir) Stat(s string) (os.FileInfo, error) {
	return os.Stat(s)
}

func (f osDir) Mkdir(s string) error {
	return os.Mkdir(s, 0755)
}

type dirInterface interface {
	Stat(s string) (os.FileInfo, error)
	Mkdir(s string) error
}

func makeDirs(p string, c dirInterface) error {
	p = clean(p)

	log.Debugf("make directory for %s", p)

	for i := 1; i < len(p); i++ {
		if p[i] == '/' {
			p1 := p[:i]
			if _, err := c.Stat(p1); err != nil {
				log.Debugf("make directory %s", p1)
				if err := c.Mkdir(p1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func passwordAuth() (string, error) {
	// read password from console
	fmt.Fprintf(os.Stdout, "Password: ")
	s, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stdout, "\n")
	return strings.Trim(string(s), " \r\n"), err
}

//
// when use pkg/sftp client transfer a big file from pkg/sftp server,
// io.Copy while cause connection hang,
// I don't known why,
// use this function has no problem
//
func copyFile(w io.Writer, r io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			_, err1 := w.Write(buf[:n])
			if err1 != nil {
				return err1
			}
		}
		if err != nil {
			if err == io.EOF {
				// trust io.EOF as success
				return nil
			}
			return err
		}
	}
}

func usage() {
	usageStr := `Usage:
  obfssh_scp -i identity_file -l login_name 
    -p port -pw password -r -obfs_method method -obfs_key key 
    -disable_obfs_after_handshake [user@]host1:]file1 ... [user@host2:]file2

Options:
    -d  verbose mode

    -i identity_file
      Specifies a identity(private key) for public key authentication.

    -l login_name
      specifies the user to log in as on the remote machine.

    -p port
      Port to connect to on the remote host
    
    -pw password
      Specifies the password for log in remote machine

    -r recursively copy the directories

    -tls
      connect to server via TLS

    -tls-insecure
	  do not verify server's certificate

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

func clean(p string) string {
	p = filepath.Clean(p)
	if os.PathSeparator != '/' {
		p = strings.Replace(p, string([]byte{os.PathSeparator}), "/", -1)
	}
	return p
}
