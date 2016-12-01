package obfssh

import (
	"io"
	"log"
)

const (
	_ = iota
	// DEBUG  log level debug
	DEBUG
	// INFO log level info
	INFO
	// ERROR log level error
	ERROR
)

// SSHLogLevel global value for log level
var SSHLogLevel = ERROR

// PipeAndClose pipe the data between c and s, close both when done
func PipeAndClose(c io.ReadWriteCloser, s io.ReadWriteCloser) {
	defer c.Close()
	defer s.Close()
	cc := make(chan int, 2)

	go func() {
		io.Copy(c, s)
		cc <- 1
	}()

	go func() {
		io.Copy(s, c)
		cc <- 1
	}()

	<-cc
}

// Log log the message by level
func Log(level int, s string, args ...interface{}) {
	if level >= SSHLogLevel {
		log.Printf(s, args...)
	}
}
