package main

import (
	"flag"
	"fmt"
	"github.com/bgentry/speakeasy"
	"github.com/fangdingjun/obfssh"
	"github.com/kr/fs"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	var user, port, pass, key string
	var recursive bool
	var obfsMethod, obfsKey string
	var disableObfsAfterHandshake bool
	var debug bool
	var hasError bool

	flag.Usage = func() {
		fmt.Printf("Usage: \n\t%s [options] user@host:path local\n\tor\n\t%s [options] local... user@host:path\n", os.Args[0], os.Args[0])

		fmt.Printf("Options:\n\n")

		flag.PrintDefaults()
	}
	flag.BoolVar(&debug, "d", false, "verbose mode")
	flag.StringVar(&port, "p", "22", "port")
	flag.StringVar(&user, "l", os.Getenv("USER"), "user")
	flag.StringVar(&pass, "pw", "", "password")
	flag.StringVar(&key, "i", "", "private key")
	flag.BoolVar(&recursive, "r", false, "recursively copy entries")
	flag.StringVar(&obfsMethod, "obfs_method", "none", "obfs encrypt method, rc4, aes or none")
	flag.StringVar(&obfsKey, "obfs_key", "", "obfs encrypt key")
	flag.BoolVar(&disableObfsAfterHandshake, "disable_obfs_after_handshake", false, "disable obfs after handshake")
	flag.Parse()

	if debug {
		obfssh.SSHLogLevel = obfssh.DEBUG
	}

	args := flag.Args()

	if len(args) < 2 {
		//fmt.Printf("Usage: \n\tscp user@host:path local\n\tor\n\tscp local... user@host:path\n")
		flag.Usage()
		os.Exit(1)
	}

	var host, path string
	r1 := ""
	var toLocal = false
	if strings.Contains(args[0], ":") {
		toLocal = true
		r1 = args[0]
	} else {
		toLocal = false
		r1 = args[len(args)-1]
	}

	if strings.Contains(r1, "@") {
		ss1 := strings.SplitN(r1, "@", 2)
		user = ss1[0]
		r1 = ss1[1]
	}
	ss2 := strings.SplitN(r1, ":", 2)
	if len(ss2) != 2 {
		//log.Fatal("Usage: \n\tscp user@host:path local\n\tor\n\tscp local... user@host:path")
		flag.Usage()
		os.Exit(1)
	}
	host = ss2[0]
	path = ss2[1]

	auths := []ssh.AuthMethod{}

	// read ssh agent and default auth key
	if pass == "" && key == "" {
		var pkeys []ssh.Signer
		if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			//auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
			if signers, err := agent.NewClient(aconn).Signers(); err == nil {
				debuglog("add private key from agent")
				pkeys = append(pkeys, signers...)
			} else {
				debuglog("get key from agent failed: %s", err)
			}
		} else {
			debuglog("dial to agent failed: %s", err)
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
					debuglog("add private key %s", k1)
				} else {
					debuglog("parse private key failed: %s", err)
				}
			}

		}

		if len(pkeys) != 0 {
			debuglog("totol %d private keys", len(pkeys))
			auths = append(auths, ssh.PublicKeys(pkeys...))
		}
	}

	if pass != "" {
		debuglog("add password auth")
		auths = append(auths, ssh.Password(pass))
	} else {
		debuglog("add keyboard interactive")
		auths = append(auths,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordAuth), 3))
	}

	if key != "" {
		if buf, err := ioutil.ReadFile(key); err == nil {
			if p, err := ssh.ParsePrivateKey(buf); err == nil {
				debuglog("add private key: %s", key)
				auths = append(auths, ssh.PublicKeys(p))
			} else {
				debuglog("parse private key failed: %s", err)
			}
		} else {
			debuglog("read private key failed: %s", err)
		}
	}

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    auths,
		Timeout: 5 * time.Second,
	}

	rhost := net.JoinHostPort(host, port)

	c, err := net.Dial("tcp", rhost)
	if err != nil {
		log.Fatal(err)
	}

	conf := &obfssh.Conf{
		ObfsMethod:                obfsMethod,
		ObfsKey:                   obfsKey,
		Timeout:                   10 * time.Second,
		KeepAliveInterval:         10 * time.Second,
		KeepAliveMax:              5,
		DisableObfsAfterHandshake: disableObfsAfterHandshake,
	}

	conn, err := obfssh.NewClient(c, config, rhost, conf)

	//conn, err := ssh.Dial("tcp", h, config)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	sftpConn, err := sftp.NewClient(conn.Client(), sftp.MaxPacket(64*1024))
	if err != nil {
		log.Fatal(err)
	}
	defer sftpConn.Close()

	// download
	if toLocal {
		localFile := args[1]
		st, err := sftpConn.Stat(path)
		if err != nil {
			log.Fatal(err)
		}

		if st.Mode().IsDir() && !recursive {
			log.Fatal("use -r to transfer the directory")
		}

		st1, err := os.Stat(localFile)
		if err == nil && !st1.Mode().IsDir() && st.Mode().IsDir() {
			log.Fatal("can't transfer directory to file")
		}

		if !st.Mode().IsDir() {
			if st1 != nil && st1.Mode().IsDir() {
				// to local directory
				bname := filepath.Base(path)
				localFile = filepath.Join(localFile, bname)
			}

			debuglog("transfer remote to local, %s -> %s", path, localFile)

			if err := get(sftpConn, path, localFile); err != nil {
				log.Fatal(err)
			}
			debuglog("done")
			return
		}

		// recursive download
		if err := rget(sftpConn, path, localFile); err != nil {
			log.Fatal(err)
		}

		// download done
		debuglog("done")

		return
	}

	// upload
	if len(args) > 2 {
		if st, err := sftpConn.Stat(path); err == nil {
			if !st.Mode().IsDir() {
				log.Fatal("multiple files can only been transferred to directory")
			}
		} else {
			log.Fatalf("remote file or directory not exists")
		}
	}

	for i := 0; i < len(args)-1; i++ {
		localFile := args[i]
		st, err := os.Stat(localFile)

		// local file not exists
		if err != nil {
			debuglog("%s", err)
			hasError = true
			continue
		}

		// directory
		if st.Mode().IsDir() {
			if !recursive {
				debuglog("omit directory %s", localFile)
				continue
			}
			// transfer directory
			if err := rput(sftpConn, localFile, path); err != nil {
				debuglog("%s", err)
				hasError = true
			}

			// next entry
			continue
		}

		// file

		remoteFile := path

		st1, err := sftpConn.Stat(path)
		if err == nil && st1.Mode().IsDir() {
			remoteFile = filepath.Join(path, filepath.Base(localFile))
		}

		if err := put(sftpConn, localFile, remoteFile); err != nil {
			hasError = true
			debuglog("upload %s failed: %s", localFile, err.Error())
		}
	}

	if hasError {
		os.Exit(1)
	}

}

func get(sftpConn *sftp.Client, remoteFile, localFile string) error {

	debuglog("download %s -> %s", remoteFile, localFile)

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

	debuglog("done")

	return nil
}

func put(sftpConn *sftp.Client, localFile, remoteFile string) error {
	debuglog("upload %s -> %s", localFile, remoteFile)

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

	debuglog("done")

	return nil
}

func rput(sftpConn *sftp.Client, localDir, remoteDir string) error {
	walker := fs.Walk(localDir)

	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		if st := walker.Stat(); !st.Mode().IsRegular() {
			debuglog("skip %s", walker.Path())
			continue
		}

		p := walker.Path()

		p1 := strings.Replace(p, localDir, "", 1)

		fmt.Println(strings.TrimLeft(p1, "/"))

		p2 := filepath.Join(remoteDir, p1)

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
	debuglog("transfer recusive from remote to local, %s -> %s", remoteDir, localDir)

	walker := sftpConn.Walk(remoteDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		if st := walker.Stat(); !st.Mode().IsRegular() {
			debuglog("skip %s", walker.Path())
			continue
		}

		p := walker.Path()
		p1 := strings.Replace(p, remoteDir, "", 1)
		p2 := filepath.Join(localDir, p1)

		fmt.Println(strings.TrimLeft(p1, "/"))

		if err := makeDirs(p2, fi{}); err != nil {
			return err
		}

		if err := get(sftpConn, p, p2); err != nil {
			return err
		}
	}

	return nil
}

type fi struct{}

func (f fi) Stat(s string) (os.FileInfo, error) {
	return os.Stat(s)
}

func (f fi) Mkdir(s string) error {
	return os.Mkdir(s, 0755)
}

type fileInterface interface {
	Stat(s string) (os.FileInfo, error)
	Mkdir(s string) error
}

func makeDirs(p string, c fileInterface) error {
	debuglog("make directory for %s", p)

	for i := 1; i < len(p); i++ {
		if p[i] == '/' {
			p1 := p[:i]
			if _, err := c.Stat(p1); err != nil {
				debuglog("make directory %s", p1)
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
	s, err := speakeasy.Ask("Password: ")
	return strings.Trim(s, " \r\n"), err
}

func debuglog(format string, args ...interface{}) {
	obfssh.Log(obfssh.DEBUG, format, args...)
}

//
// when use pkg/sftp client transfer a big file from pkg/sftp server,
// io.Copy while cause connection hang,
// I don't known why,
// use this function has no problem
//
func copyFile(w io.Writer, r io.Reader) error {
	buf := make([]byte, 34*1024)
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
