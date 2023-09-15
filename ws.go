package obfssh

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	*websocket.Conn
	r io.Reader
}

var _ net.Conn = &wsConn{}

func (wc *wsConn) Read(buf []byte) (int, error) {
	for {
		if wc.r == nil {
			_, r, err := wc.NextReader()
			if err != nil {
				return 0, err
			}
			wc.r = r
		}
		n, err := wc.r.Read(buf)
		if err != nil {
			wc.r = nil
			if err == io.EOF {
				// current message is read out
				if n > 0 {
					return n, nil
				}
				// no data, read next message
				continue
			}
		}
		return n, err
	}
}

func (wc *wsConn) Write(buf []byte) (int, error) {
	err := wc.WriteMessage(websocket.BinaryMessage, buf)
	return len(buf), err
}

func (wc *wsConn) SetDeadline(t time.Time) error {
	if err := wc.SetReadDeadline(t); err != nil {
		return err
	}
	if err := wc.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}
