package obfssh

import (
	"io"

	"github.com/fangdingjun/go-log"
)

// PipeAndClose pipe the data between c and s, close both when done
func PipeAndClose(c io.ReadWriteCloser, s io.ReadWriteCloser) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("recovered: %+v", err)
		}
	}()
	defer c.Close()
	defer s.Close()
	cc := make(chan struct{}, 2)

	go func() {
		io.Copy(c, s)
		cc <- struct{}{}
	}()

	go func() {
		io.Copy(s, c)
		cc <- struct{}{}
	}()

	<-cc
}
