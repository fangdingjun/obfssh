package obfssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	//"log"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	keyLength         = 16
	seedLength        = 16
	maxPadding        = 1024
	magicValue uint32 = 0x0BF5CA7E
	loopCount         = 10
)

// ObfsConn implement the net.Conn interface which enrytp/decrpt
// the data automatic
type ObfsConn struct {
	net.Conn
	key            []byte
	cipherRead     cipher.Stream
	cipherWrite    cipher.Stream
	cipherDisabled bool
	method         string
	writeBuf       []byte
	writeBufLen    int
	//isServer bool
}

// NewObfsConn initial a ObfsConn
// after new return, seed handshake is done
func NewObfsConn(c net.Conn, method, key string, isServer bool) (*ObfsConn, error) {

	wc := &ObfsConn{
		Conn:           c,
		key:            []byte(key),
		cipherDisabled: false,
		method:         method,
		writeBuf:       make([]byte, 8192),
		writeBufLen:    8192,
		// isServer: isServer,
	}

	// do not initial chiper when encrypt method is empty or none
	if method == "" || method == "none" {
		wc.DisableObfs()
		return wc, nil
	}

	if isServer {
		if err := wc.readSeed(); err != nil {
			buf := make([]byte, 1024)
			Log(DEBUG, "read forever")
			// read forever
			for {
				if _, err1 := wc.Conn.Read(buf); err1 != nil {
					return nil, err
				}
			}
			return nil, err
		}
	} else {
		if err := wc.writeSeed(); err != nil {
			return nil, err
		}
	}
	return wc, nil
}

func generateKey(seed, keyword, iv []byte) []byte {
	buf := make([]byte, seedLength+len(keyword)+len(iv))

	copy(buf[0:], seed)

	// user key
	if keyword != nil {
		copy(buf[seedLength:], keyword)
	}

	copy(buf[seedLength+len(keyword):], iv)

	o := sha512.Sum512(buf[0:])

	for i := 0; i < loopCount; i++ {
		o = sha512.Sum512(o[0:])
	}

	return o[0:keyLength]
}

// EnableObfs enable the encryption
func (wc *ObfsConn) EnableObfs() {
	Log(DEBUG, "enable the encryption")
	wc.cipherDisabled = false
}

// DisableObfs disable the encryption
func (wc *ObfsConn) DisableObfs() {
	Log(DEBUG, "disable the encryption")
	wc.cipherDisabled = true
}

func (wc *ObfsConn) writeSeed() error {
	Log(DEBUG, "begin to write the seed")

	ii, err := rand.Int(rand.Reader, big.NewInt(int64(maxPadding)))
	if err != nil {
		//Log(ERROR, "initial the random seed failed: %s", err.Error())
		return err
	}
	i := ii.Int64()
	Log(DEBUG, "use padding data length %d\n", int(i))
	buf := make([]byte, seedLength+8+int(i))

	// generate seed
	rand.Read(buf[0:seedLength])

	// put magic value
	binary.BigEndian.PutUint32(buf[seedLength:seedLength+4], magicValue)

	// put padding length
	binary.BigEndian.PutUint32(buf[seedLength+4:seedLength+8], uint32(i))

	// generate padding data
	rand.Read(buf[24:])

	// generate the key
	keyToServer := generateKey(buf[0:seedLength], wc.key, []byte("client_to_server"))
	keyToClient := generateKey(buf[0:seedLength], wc.key, []byte("server_to_client"))

	var r, w cipher.Stream

	// initial the cipher
	switch strings.ToLower(wc.method) {
	case "aes":
		w, r = newAESCipher(keyToServer, keyToClient)
	case "rc4":
		w, r = newRC4Cipher(keyToServer, keyToClient)
	default:
		return errors.New("unknown cipher type")
	}

	wc.cipherWrite = w
	wc.cipherRead = r

	// encrypt the data, except the seed
	wc.cipherWrite.XORKeyStream(buf[seedLength:], buf[seedLength:])

	_, err = wc.Conn.Write(buf[0:])
	if err != nil {
		return err
	}

	Log(DEBUG, "write seed done")
	return nil
}

func (wc *ObfsConn) readSeed() error {
	Log(DEBUG, "begin to read the seed")
	buf := make([]byte, seedLength+8)

	// read the data except padding
	_, err := io.ReadFull(wc.Conn, buf)
	if err != nil {
		return err
	}

	// generate the key
	keyToServer := generateKey(buf[0:seedLength], wc.key, []byte("client_to_server"))
	keyToClient := generateKey(buf[0:seedLength], wc.key, []byte("server_to_client"))

	var w, r cipher.Stream
	switch strings.ToLower(wc.method) {
	case "aes":
		w, r = newAESCipher(keyToClient, keyToServer)
	case "rc4":
		w, r = newRC4Cipher(keyToClient, keyToServer)
	}

	wc.cipherWrite = w
	wc.cipherRead = r

	// decrypt the magic and padding length
	wc.cipherRead.XORKeyStream(buf[seedLength:seedLength+8], buf[seedLength:seedLength+8])

	// check magic value
	magic := binary.BigEndian.Uint32(buf[seedLength : seedLength+4])
	if magic != magicValue {
		Log(ERROR, "magic %x check failed from %s", magic, wc.Conn.RemoteAddr())
		return errors.New("wrong magic value")
	}

	// read the padding data
	padLen := binary.BigEndian.Uint32(buf[seedLength+4 : seedLength+8])

	Log(DEBUG, "padding %d", padLen)

	buf = make([]byte, padLen)
	if _, err := io.ReadFull(wc, buf[0:]); err != nil {
		return err
	}

	Log(DEBUG, "read seed done")
	return nil
}

// Read read the data from underlying connection
// if encryption enabled, decrypt the data and return to plain data to upstream
func (wc *ObfsConn) Read(buf []byte) (int, error) {
	n, err := wc.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if !wc.cipherDisabled {
		wc.cipherRead.XORKeyStream(buf[0:n], buf[0:n])
	}
	//log.Printf("%+q", buf[0:n])
	return n, err
}

// Write write the data to underlying connection
// if encryption enabled, encrypt it before write
func (wc *ObfsConn) Write(buf []byte) (int, error) {
	if !wc.cipherDisabled {
		bufLen := len(buf)
		if bufLen > wc.writeBufLen {
			wc.writeBufLen = bufLen + 8192
			wc.writeBuf = make([]byte, wc.writeBufLen)
		}
		wc.cipherWrite.XORKeyStream(wc.writeBuf[0:bufLen], buf[0:bufLen])
		return wc.Conn.Write(wc.writeBuf[0:bufLen])
	}
	return wc.Conn.Write(buf[0:])
}

func newAESCipher(key1, key2 []byte) (cipher.Stream, cipher.Stream) {
	b1, _ := aes.NewCipher(key1)
	b2, _ := aes.NewCipher(key2)

	m1 := sha1.Sum(key1)
	iv1 := md5.Sum(m1[0:])

	m2 := sha1.Sum(key2)
	iv2 := md5.Sum(m2[0:])

	w := cipher.NewCFBEncrypter(b1, iv1[0:])
	r := cipher.NewCFBDecrypter(b2, iv2[0:])
	return w, r
}

func newRC4Cipher(key1, key2 []byte) (cipher.Stream, cipher.Stream) {
	w, _ := rc4.NewCipher(key1)
	r, _ := rc4.NewCipher(key2)
	return w, r
}

// TimedOutConn is a net.Conn with read/write timeout set
type TimedOutConn struct {
	net.Conn
	Timeout time.Duration
}

func (tc *TimedOutConn) Read(b []byte) (int, error) {
	tc.Conn.SetDeadline(time.Now().Add(tc.Timeout))
	return tc.Conn.Read(b)
}

func (tc *TimedOutConn) Write(b []byte) (int, error) {
	tc.Conn.SetDeadline(time.Now().Add(tc.Timeout))
	return tc.Conn.Write(b)
}
