//go:build windows

package quic

import "golang.org/x/sys/windows"

// sendPathErrs: the errors isSendPathErr treats as a lost packet.
var sendPathErrs = []error{windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH, windows.WSAEADDRNOTAVAIL, windows.WSAENETDOWN}
