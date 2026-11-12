//go:build !darwin

package quic

import "github.com/nfltr/quic-go/internal/protocol"

// connectedDeliver: no connected sockets.
type connectedDeliver struct{}

// connectedSend: only darwin sends on a connected socket
// (sys_conn_connected_darwin.go).
type connectedSend struct{}

func (*connectedSend) write(*sconn, *remoteAddrInfo, []byte, protocol.ECN) (bool, error) {
	return false, nil
}

func (*connectedSend) tryWrite(*sconn, *remoteAddrInfo, []byte, protocol.ECN) (handled, ok bool) {
	return false, false
}

// setConnectedDeliver: no connected sockets.
func setConnectedDeliver(rawConn, func(receivedPacket)) {}

func (*connectedSend) reset() {}

func (*connectedSend) close() {}
