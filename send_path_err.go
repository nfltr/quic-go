//go:build !windows

package quic

import "syscall"

// sendPathErrs: the errors isSendPathErr treats as a lost packet.
var sendPathErrs = []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EADDRNOTAVAIL, syscall.ENETDOWN}
