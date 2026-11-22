package quic

import (
	"net"
	"testing"
)

type bufferRecordingConn struct {
	net.PacketConn
	read, write int
}

func (c *bufferRecordingConn) SetReadBuffer(n int) error  { c.read = n; return nil }
func (c *bufferRecordingConn) SetWriteBuffer(n int) error { c.write = n; return nil }

// A Transport asks a send buffer of SocketSendBufferWanted, not the 7 MiB
// it asks to receive: a send buffer that large let one connection queue
// ~5,000 packets (40-55 ms) in the host's qdisc, whose CoDel (fq_codel,
// target 5 ms) dropped whole 44-packet GSO batches: 0.08-0.14 % of the
// packets of a 4-connection Helsinki -> Singapore run declared lost and
// resent; with 512 KiB none (lane FORKLEFT). Transport.SendBufferSize
// still asks more.
func TestTransportSendBufferDefault(t *testing.T) {
	for _, tc := range []struct {
		o           sockOpts
		read, write int
	}{
		{sockOpts{}, SocketBufferWanted, SocketSendBufferWanted},
		{sockOpts{rcvBuf: 1 << 20, sndBuf: 4 << 20}, 1 << 20, 4 << 20},
	} {
		c := &bufferRecordingConn{PacketConn: newUDPConnLocalhost(t)}
		if _, err := wrapConn(c, tc.o); err != nil {
			t.Fatal(err)
		}
		if c.read != tc.read || c.write != tc.write {
			t.Fatalf("%+v: asked receive %d, send %d: want %d, %d", tc.o, c.read, c.write, tc.read, tc.write)
		}
	}
	if SocketSendBufferWanted > 512<<10 {
		t.Fatalf("SocketSendBufferWanted %d: want at most 512 KiB (a few ms at 1 Gbit/s)", SocketSendBufferWanted)
	}
}
