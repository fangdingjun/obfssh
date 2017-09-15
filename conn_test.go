package obfssh

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func testTimedOutConn(t *testing.T, timeout bool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %s", err)
	}

	// timeout time
	timeout := 1 * time.Second

	defer l.Close()

	addr := l.Addr()

	go func() {
		s, err := l.Accept()
		if err != nil {
			t.Fatalf("accept failed: %s", err)
		}

		defer s.Close()

		sConn := TimedOutConn{s, timeout}

		buf := make([]byte, 100)

		n, err := sConn.Read(buf)
		if err != nil {
			t.Fatalf("server read failed: %s", err)
		}

		if timeout {
			time.Sleep(timeout + 1*time.Second)
		}

		sConn.Write(buf[:n])
	}()

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}

	defer c.Close()

	str := "hello, world"

	cConn := TimedOutConn{c, timeout}

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
