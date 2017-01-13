// +build linux, !386
// +build linux

package obfssh

import (
	"syscall"
)

// getsockopt syscall number
const sysGetSockOpt = syscall.SYS_GETSOCKOPT
