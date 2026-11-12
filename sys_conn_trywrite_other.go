//go:build linux || freebsd

package quic

import (
	"net"

	"github.com/nfltr/quic-go/internal/protocol"
)

type familyOnce struct{}

// tryWritePacket: only darwin sends inline (sys_conn_trywrite_darwin.go).
func (c *oobConn) tryWritePacket([]byte, net.Addr, []byte, protocol.ECN) bool { return false }
