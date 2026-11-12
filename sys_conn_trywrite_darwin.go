//go:build darwin

package quic

import (
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/nfltr/quic-go/internal/protocol"
)

// familyOnce is the socket's address family, read once.
type familyOnce struct {
	once sync.Once
	v    int // unix.AF_INET, unix.AF_INET6; 0: unknown
}

func (f *familyOnce) get(raw syscall.RawConn) int {
	f.once.Do(func() {
		_ = raw.Control(func(fd uintptr) {
			switch sa, _ := unix.Getsockname(int(fd)); sa.(type) {
			case *unix.SockaddrInet4:
				f.v = unix.AF_INET
			case *unix.SockaddrInet6:
				f.v = unix.AF_INET6
			}
		})
	})
	return f.v
}

// tryWritePacket (nfltr fork) sends b to addr in one non-blocking sendmsg
// on the caller's goroutine. It reports false, having sent nothing, when
// the socket would block or on any error: the caller then sends b the
// usual way (the send queue), which handles the error as before. macOS has
// no UDP segmentation offload, so a connection sends one packet per
// syscall; handing each burst to the send queue's goroutine cost a
// wake-up of that goroutine (and of an idle P spinning for it) per burst.
// Guard: TestSendQueueWritesInline; the gain: github.com/nfltr/link
// peerlink/quiclink BenchmarkBulkCPU.
func (c *oobConn) tryWritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, ecn protocol.ECN) bool {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || c.raw == nil {
		return false
	}
	var sa unix.Sockaddr
	switch c.family.get(c.raw) {
	case unix.AF_INET:
		ip4 := ua.IP.To4()
		if ip4 == nil {
			return false
		}
		s := &unix.SockaddrInet4{Port: ua.Port}
		copy(s.Addr[:], ip4)
		sa = s
	case unix.AF_INET6:
		ip16 := ua.IP.To16()
		if ip16 == nil || ua.Zone != "" {
			return false
		}
		s := &unix.SockaddrInet6{Port: ua.Port}
		copy(s.Addr[:], ip16)
		sa = s
	default:
		return false
	}
	oob := c.appendOOB(packetInfoOOB, addr, 0, ecn)
	var err error
	if cerr := c.raw.Write(func(fd uintptr) bool {
		_, err = unix.SendmsgN(int(fd), b, oob, sa, 0)
		return true // one attempt: never wait for the socket
	}); cerr != nil {
		return false
	}
	return err == nil
}
