package obfssh

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestObfsConn(t *testing.T) {
	obfsMethod := "rc4"
	obfsKey := "hello"

	// test rc4
	testObfsConn(t, obfsMethod, obfsKey)

	obfsMethod = "aes"

	// test aes
	testObfsConn(t, obfsMethod, obfsKey)
}

func testObfsConn(t *testing.T, obfsMethod, obfsKey string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socket failed: %s", err)
	}

	defer l.Close()

	addr := l.Addr()

	go func() {
		// server
		s, err := l.Accept()
		if err != nil {
			t.Fatalf("acceept failed: %s", err)
		}

		defer s.Close()

		sConn, err := NewObfsConn(s, obfsMethod, obfsKey, true)
		if err != nil {
			t.Fatalf("create obfsconn failed: %s", err)
		}

		buf := make([]byte, 100)
		n, err := sConn.Read(buf)
		if err != nil {
			t.Fatalf("server read failed: %s", err)
		}

		sConn.Write(buf[:n])
	}()

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dail failed: %s", err)
	}

	defer c.Close()

	cConn, err := NewObfsConn(c, obfsMethod, obfsKey, false)
	if err != nil {
		t.Fatalf("create client obfsconn failed: %s", err)
	}

	str := "hello, world"
	cConn.Write([]byte(str))

	buf := make([]byte, 100)
	n, err := cConn.Read(buf)

	if str != string(buf[:n]) {
		t.Errorf("data transport failed")
	}
}

func TestTimedOutConn(t *testing.T) {
	testTimedOutConn(t, false)
	testTimedOutConn(t, true)
}

func testTimedOutConn(t *testing.T, timeout bool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %s", err)
	}

	// timeout time
	timeout_t := 1 * time.Second

	defer l.Close()

	addr := l.Addr()

	go func() {
		s, err := l.Accept()
		if err != nil {
			t.Fatalf("accept failed: %s", err)
		}

		defer s.Close()

		sConn := TimedOutConn{s, timeout_t}

		buf := make([]byte, 100)

		n, err := sConn.Read(buf)
		if err != nil {
			t.Fatalf("server read failed: %s", err)
		}

		if timeout {
			time.Sleep(timeout_t + 1*time.Second)
		}

		sConn.Write(buf[:n])
	}()

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}

	defer c.Close()

	str := "hello, world"

	cConn := TimedOutConn{c, timeout_t}

	if _, err := cConn.Write([]byte(str)); err != nil {
		t.Fatalf("client write failed: %s", err)
	}

	buf := make([]byte, 100)

	n, err := cConn.Read(buf)
	if timeout {
		if err == nil {
			t.Errorf("expeced timeout error, got nil")
		} else {
			fmt.Println(err)
		}
	} else {
		if str != string(buf[:n]) {
			t.Errorf("data transport failed")
		}
	}
}
