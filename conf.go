package obfssh

import (
	"time"
)

// Conf keeps the configure of server or client
type Conf struct {
	// ObfsMethod is the encrpt method
	ObfsMethod string

	// ObfsKey is key for encrypt
	ObfsKey string

	// Timeout is the socket timeout on read/write
	Timeout time.Duration

	// DisableObfsAfterHandShake disable the obfs encryption after ssh handshake done
	DisableObfsAfterHandshake bool

	// KeepAliveInterval  the keep alive interval
	KeepAliveInterval time.Duration

	// KeepAliveMax the max times of keep alive error
	KeepAliveMax int
}
