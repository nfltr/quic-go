package quic

import (
	"errors"
	"net"
	"syscall"
)

// SocketBufferWanted is the receive buffer size quic-go asks a socket
// for.
const SocketBufferWanted = desiredBufferSize

// SocketSendBufferWanted is the send buffer size quic-go asks a socket
// for: what a connection may queue in the host (its qdisc) is a few ms at
// 1 Gbit/s, as Linux's TCP Small Queues keeps it for TCP (the old
// tcp_limit_output_bytes, 256 KiB), so the host's AQM (fq_codel's CoDel,
// target 5 ms) does not drop whole GSO batches (lane FORKLEFT).
const SocketSendBufferWanted = 256 << 10

// SocketBuffers returns the receive and send buffer sizes the host gave
// c's socket (SO_RCVBUF, SO_SNDBUF; Linux reports twice what it reserves
// for data, its bookkeeping included). A host whose limit is lower than
// SocketBufferWanted or SocketSendBufferWanted (Linux net.core.rmem_max,
// wmem_max) gives less
// without an error; quic-go logs it only at debug level.
func SocketBuffers(c net.PacketConn) (read, write int, err error) {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, 0, errors.New("connection has no SyscallConn. Not a *net.UDPConn?")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	if read, err = inspectReadBuffer(rc); err != nil {
		return 0, 0, err
	}
	write, err = inspectWriteBuffer(rc)
	return read, write, err
}
