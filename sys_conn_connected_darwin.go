//go:build darwin

package quic

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/nfltr/quic-go/internal/protocol"
)

// connectThreshold is how many packets a connection sends on the shared
// socket before it connects one of its own: short connections (a punch's
// losing candidates, an address query) never open a socket.
const connectThreshold = 64

// connectedSend (nfltr fork): on macOS a sendmsg on an unconnected UDP
// socket to a non-loopback address pays a route and policy lookup per
// packet, about 6x the cost of a send on a connected socket (M5, 1400-byte
// packets: 16.6 against 2.9 µs of CPU per packet, both ends, to the host's
// own LAN address; 32 against 17 µs to another host on the LAN). Once a
// connection on an *oobConn has sent connectThreshold packets, it opens a
// second socket bound to the connection's local address (the shared
// socket's port, both with SO_REUSEPORT) and connected to the remote
// address, and sends on it. The kernel then delivers the remote's
// datagrams to that socket (the most specific match); a goroutine reads
// them into the transport (oobConn.deliver), as if read on the shared
// socket, so routing by connection ID is unchanged and a packet read on
// either socket reaches its connection. A failure to open it leaves the
// connection on the shared socket; a send on a socket closed meanwhile
// (reset by a remote address change or the connection's end) goes out on
// the shared socket. Guard: TestConnectedSend*; the gain:
// docs/decisions/mac-quic-connected-send-2026-11-13.md in github.com/nfltr/nfltr.
type connectedSend struct {
	mu     sync.Mutex
	sock   atomic.Pointer[connectedSock]
	sent   atomic.Uint32 // packets sent on the shared socket since the last reset
	failed atomic.Bool   // opening failed for this remote address
}

// connectedSock is the connected socket and its reader.
type connectedSock struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	oob  *oobConn
}

// connectedDeliver is the transport's handler of a packet read on a
// connection's connected socket.
type connectedDeliver func(receivedPacket)

// setConnectedDeliver has packets read on a connection's connected socket
// handled by deliver (the transport's packet handler).
func setConnectedDeliver(conn rawConn, deliver func(receivedPacket)) {
	if oc, ok := conn.(*oobConn); ok {
		oc.deliver = deliver
	}
}

// get returns the connected socket, opening it once the connection has
// sent enough packets; nil: send on the shared socket.
func (s *connectedSend) get(c *sconn, ai *remoteAddrInfo) *connectedSock {
	if cs := s.sock.Load(); cs != nil {
		return cs
	}
	if s.failed.Load() || s.sent.Add(1) < connectThreshold {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cs := s.sock.Load(); cs != nil || s.failed.Load() {
		return cs
	}
	cs, err := openConnected(c, ai.addr)
	if err != nil {
		s.failed.Store(true)
		if c.logger.Debug() {
			c.logger.Debugf("no connected socket to %s: %s", ai.addr, err)
		}
		return nil
	}
	s.sock.Store(cs)
	go cs.read(s)
	return cs
}

// write sends p on the connected socket, waiting while the socket is
// full; false: not sent, send it on the shared socket.
func (s *connectedSend) write(c *sconn, ai *remoteAddrInfo, p []byte, ecn protocol.ECN) (bool, error) {
	cs := s.get(c, ai)
	if cs == nil {
		return false, nil
	}
	return s.outcome(cs, cs.send(p, cs.oob.appendOOB(nil, ai.addr, 0, ecn), true))
}

// tryWrite sends p in one non-blocking sendmsg on the connected socket
// (as oobConn.tryWritePacket); handled false: no connected socket.
func (s *connectedSend) tryWrite(c *sconn, ai *remoteAddrInfo, p []byte, ecn protocol.ECN) (handled, ok bool) {
	cs := s.get(c, ai)
	if cs == nil {
		return false, false
	}
	err := cs.send(p, cs.oob.appendOOB(nil, ai.addr, 0, ecn), false)
	if err == unix.EAGAIN {
		return true, false // full: the send queue sends it
	}
	sent, err := s.outcome(cs, err)
	return true, sent && err == nil
}

// send is one sendmsg of p on the connected socket (no address: the net
// package does not know the socket is connected); wait: retry while the
// socket is full, else one attempt (EAGAIN when full).
func (cs *connectedSock) send(p, oob []byte, wait bool) error {
	var err error
	if cerr := cs.raw.Write(func(fd uintptr) bool {
		_, err = unix.SendmsgN(int(fd), p, oob, nil, 0)
		return !wait || err != unix.EAGAIN
	}); cerr != nil {
		err = cerr
	}
	return err
}

// outcome maps a send's error. A closed socket is no send: the caller
// uses the shared socket. A path error (isSendPathErr: the local address
// the socket was connected from is gone, the host changed networks) drops
// the socket, whose source address is fixed at connect, so the shared
// socket sends this packet from whatever address the host has now (the
// peer sees the client's new address, as without a connected socket) and
// a new socket is connected after connectThreshold more packets. An ICMP
// error a connected socket reports for an earlier datagram (ECONNREFUSED)
// is a lost packet, as on the unconnected shared socket, which never sees
// it.
func (s *connectedSend) outcome(cs *connectedSock, err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, net.ErrClosed):
		return false, nil
	case isSendPathErr(err):
		s.drop(cs, false)
		return false, nil
	case errors.Is(err, unix.ECONNREFUSED):
		return true, nil
	}
	return true, err
}

// read hands the connected socket's packets to the transport until the
// socket is closed or fails; a failed socket is closed, so the remote's
// datagrams reach the shared socket again.
func (cs *connectedSock) read(s *connectedSend) {
	defer s.drop(cs, true)
	for {
		p, err := cs.oob.ReadPacket()
		if err != nil {
			if errors.Is(err, unix.ECONNREFUSED) {
				// an earlier datagram's ICMP error; the batch read nothing,
				// so read anew (ReadPacket would hand out the batch's
				// stale messages)
				cs.oob.messages, cs.oob.readPos = cs.oob.messages[:0], 0
				continue
			}
			return
		}
		cs.oob.deliver(p)
	}
}

// drop closes cs if it is still the connected socket; failed: do not
// open another for this remote address, else count again.
func (s *connectedSend) drop(cs *connectedSock, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sock.CompareAndSwap(cs, nil) {
		_ = cs.conn.Close()
		s.sent.Store(0)
		if failed {
			s.failed.Store(true)
		}
	}
}

// reset closes the connected socket and starts counting again (a new
// remote address).
func (s *connectedSend) reset() { s.closeSock(false) }

// close closes the connected socket for good (the connection's end).
func (s *connectedSend) close() { s.closeSock(true) }

func (s *connectedSend) closeSock(final bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cs := s.sock.Swap(nil); cs != nil {
		_ = cs.conn.Close()
	}
	s.sent.Store(0)
	s.failed.Store(final)
}

// openConnected opens a UDP socket bound to the connection's local
// address on the shared socket's port and connected to remote.
func openConnected(c *sconn, remote net.Addr) (*connectedSock, error) {
	shared, ok := c.rawConn.(*oobConn)
	if !ok || shared.raw == nil || shared.deliver == nil {
		return nil, errors.New("not an oobConn of a transport")
	}
	ra, ok := remote.(*net.UDPAddr)
	la, ok2 := c.localAddr.(*net.UDPAddr)
	if !ok || !ok2 || ra.Zone != "" || la.Zone != "" {
		return nil, errors.New("not a UDP address without zone")
	}
	family := shared.family.get(shared.raw)
	rsa, err := sockaddr(family, ra.IP, ra.Port)
	if err != nil {
		return nil, err
	}
	lsa, err := sockaddr(family, la.IP, la.Port)
	if err != nil {
		return nil, err
	}
	v6only := 0
	var serr error
	if err := shared.raw.Control(func(fd uintptr) {
		// SO_REUSEPORT on both sockets lets the second bind the port.
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		if serr == nil && family == unix.AF_INET6 {
			v6only, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		}
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "quic-connected") // #nosec G115 -- a descriptor
	defer f.Close()
	if err := setupConnected(fd, family, v6only, lsa, rsa); err != nil {
		return nil, err
	}
	pc, err := net.FilePacketConn(f) // a dup of fd, non-blocking on the poller
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("not a UDP socket")
	}
	rc, err := wrapConn(conn) // buffers, DF, ECN and packet info as the shared socket
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	oob, ok := rc.(*oobConn)
	if !ok || oob.raw == nil {
		_ = conn.Close()
		return nil, errors.New("not an oobConn")
	}
	oob.deliver = shared.deliver
	return &connectedSock{conn: conn, raw: oob.raw, oob: oob}, nil
}

func setupConnected(fd, family, v6only int, lsa, rsa unix.Sockaddr) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}
	if family == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only); err != nil {
			return err
		}
	}
	if err := unix.Bind(fd, lsa); err != nil {
		return err
	}
	return unix.Connect(fd, rsa)
}

// sockaddr is ip:port in the socket's family (an IPv4 address mapped on
// an IPv6 socket).
func sockaddr(family int, ip net.IP, port int) (unix.Sockaddr, error) {
	switch family {
	case unix.AF_INET:
		ip4 := ip.To4()
		if ip4 == nil {
			if !ip.IsUnspecified() {
				return nil, errors.New("not an IPv4 address")
			}
			ip4 = net.IPv4zero.To4()
		}
		s := &unix.SockaddrInet4{Port: port}
		copy(s.Addr[:], ip4)
		return s, nil
	case unix.AF_INET6:
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, errors.New("not an IP address")
		}
		if ip.To4() != nil && ip.IsUnspecified() {
			ip16 = net.IPv6unspecified // 0.0.0.0 on a dual-stack socket: any address
		}
		s := &unix.SockaddrInet6{Port: port}
		copy(s.Addr[:], ip16)
		return s, nil
	}
	return nil, errors.New("unknown address family")
}
