package obfssh

import (
	"net"
	"time"
)

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
