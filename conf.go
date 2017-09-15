package obfssh

import (
	"time"
)

// Conf keeps the configure of server or client
type Conf struct {

	// Timeout is the socket timeout on read/write
	Timeout time.Duration

	// KeepAliveInterval  the keep alive interval
	KeepAliveInterval time.Duration

	// KeepAliveMax the max times of keep alive error
	KeepAliveMax int
}
