package obfssh

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/fangdingjun/go-log/v5"
)

func TestTimedOutConn(t *testing.T) {
	testTimedOutConn(t, true)
	testTimedOutConn(t, false)
}

func testTimedOutConn(t *testing.T, _timeout bool) {
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
			log.Errorf("accept failed: %s", err)
			return
		}

		defer s.Close()

		sConn := TimedOutConn{s, timeout}

		buf := make([]byte, 100)

		n, err := sConn.Read(buf)
		if err != nil {
			log.Errorf("server read failed: %s", err)
			return
		}

		if _timeout {
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
	if _timeout {
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
