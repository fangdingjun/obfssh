//go:build !linux
// +build !linux

package obfssh

import (
	"net"
)

func getOriginDst(c net.Conn) (net.Addr, error) {
	return c.LocalAddr(), nil
}
