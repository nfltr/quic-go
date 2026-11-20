//go:build !windows

package quic

import "syscall"

// sendPathErrs: the errors isSendPathErr treats as a lost packet. EPERM is
// a local firewall's drop (iptables/nftables DROP in OUTPUT); a new socket's
// first EPERM is retried before (send_conn.go isPermissionError).
var sendPathErrs = []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EADDRNOTAVAIL, syscall.ENETDOWN, syscall.EPERM}
