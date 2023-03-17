package obfssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/fangdingjun/go-log/v5"
	"github.com/gorilla/websocket"
)

type wsConn struct {
	*websocket.Conn
	buf *bytes.Buffer
	mu  *sync.Mutex
	ch  chan struct{}
}

var _ net.Conn = &wsConn{}

func (wc *wsConn) readLoop() {
	for {
		_, data, err := wc.ReadMessage()
		if err != nil {
			log.Debugln(err)
			close(wc.ch)
			break
		}

		wc.mu.Lock()
		wc.buf.Write(data)
		wc.mu.Unlock()

		select {
		case wc.ch <- struct{}{}:
		default:
		}
	}
}

func (wc *wsConn) Read(buf []byte) (int, error) {
	wc.mu.Lock()

	n, err := wc.buf.Read(buf)
	if err == nil {
		wc.mu.Unlock()
		return n, err
	}

	wc.mu.Unlock()

	if err != io.EOF {
		return 0, err
	}

	// EOF, no data avaliable, read again
	select {
	case _, ok := <-wc.ch:
		if !ok {
			return 0, errors.New("connection closed")
		}
	}

	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.buf.Read(buf)
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
