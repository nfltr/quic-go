//go:build linux

package quic

import (
	"bytes"
	"net"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/nfltr/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// groBatchConn returns, in one ReadBatch, the messages it holds: each a
// coalesced buffer with its UDP_GRO segment size and IP_TOS (ECN).
type groBatchConn struct {
	msgs  [][]byte
	segs  []int
	ecn   []protocol.ECN
	calls int
}

func (c *groBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	c.calls++
	if c.calls > 1 {
		return 0, net.ErrClosed
	}
	for i, m := range c.msgs {
		ms[i].N = copy(ms[i].Buffers[0], m)
		oob := ms[i].OOB[:0]
		if c.segs[i] > 0 {
			oob = appendCmsgInt(oob, unix.IPPROTO_UDP, unix.UDP_GRO, c.segs[i])
		}
		oob = appendIPv4ECNMsg(oob, c.ecn[i])
		ms[i].Buffers[0] = ms[i].Buffers[0][:cap(ms[i].Buffers[0])]
		ms[i].NN = len(oob)
		ms[i].OOB = ms[i].OOB[:cap(ms[i].OOB)]
		copy(ms[i].OOB, oob)
	}
	return len(c.msgs), nil
}

func appendCmsgInt(b []byte, level, typ int32, v int) []byte {
	start := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(4))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[start]))
	h.Level, h.Type = level, typ
	h.SetLen(unix.CmsgLen(4))
	*(*int32)(unsafe.Pointer(&b[start+unix.CmsgSpace(0)])) = int32(v)
	return b
}

// TestGROSplitsACoalescedBuffer: every datagram the kernel coalesced
// reaches the connection once, in its order, the last one shorter, each
// with its buffer's ECN mark; a message without the control message is
// one datagram.
func TestGROSplitsACoalescedBuffer(t *testing.T) {
	c, err := newConn(newUDPConnLocalhost(t), true)
	require.NoError(t, err)
	if !c.capabilities().GRO {
		t.Skip("no UDP_GRO on this kernel")
	}
	bc := &groBatchConn{
		msgs: [][]byte{[]byte("aaaaabbbbbccc"), []byte("single"), []byte("ddddeeee")},
		segs: []int{5, 0, 4},
		ecn:  []protocol.ECN{protocol.ECNCE, protocol.ECT0, protocol.ECT1},
	}
	c.batchConn = bc
	want := []struct {
		data string
		ecn  protocol.ECN
	}{{"aaaaa", protocol.ECNCE}, {"bbbbb", protocol.ECNCE}, {"ccc", protocol.ECNCE}, {"single", protocol.ECT0}, {"dddd", protocol.ECT1}, {"eeee", protocol.ECT1}}
	for _, w := range want {
		p, err := c.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, w.data, string(p.data))
		require.Equal(t, w.ecn, p.ecn)
		require.Equal(t, protocol.ByteCount(len(w.data)), p.buffer.Len())
		p.buffer.Release()
	}
	_, err = c.ReadPacket()
	require.ErrorIs(t, err, net.ErrClosed)
}

// countingBatchConn counts the messages a real socket returns.
type countingBatchConn struct {
	batchConn
	msgs int
}

func (c *countingBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := c.batchConn.ReadBatch(ms, flags)
	c.msgs += n
	return n, err
}

// gsoBatch sends segs datagrams of seg bytes (the last last bytes) in one
// GSO sendmsg from a socket of its own to addr, and returns their bytes.
func gsoBatch(t *testing.T, addr net.Addr, segs, seg, last int) [][]byte {
	t.Helper()
	conn, err := newConn(newUDPConnLocalhost(t), true)
	require.NoError(t, err)
	require.True(t, conn.capabilities().GSO)
	var all []byte
	var want [][]byte
	for i := range segs {
		n := seg
		if i == segs-1 {
			n = last
		}
		d := bytes.Repeat([]byte{byte(i)}, n)
		want = append(want, d)
		all = append(all, d...)
	}
	_, err = conn.WritePacket(all, addr, nil, uint16(seg), protocol.ECNUnsupported)
	require.NoError(t, err)
	return want
}

// TestGROReceivesAGSOBatch: a full GSO batch (44 packets of 1452 bytes,
// the last shorter) sent in one sendmsg arrives as its 44 packets, in
// order, in fewer messages than packets (GRO coalesced them).
func TestGROReceivesAGSOBatch(t *testing.T) {
	segs := int(protocol.MaxLargePacketBufferSize / protocol.MaxPacketBufferSize)
	require.Equal(t, 44, segs)
	udpConn := newUDPConnLocalhost(t)
	c, err := newConn(udpConn, true)
	require.NoError(t, err)
	if !c.capabilities().GRO {
		t.Skip("no UDP_GRO on this kernel")
	}
	cb := &countingBatchConn{batchConn: c.batchConn}
	c.batchConn = cb
	want := gsoBatch(t, udpConn.LocalAddr(), segs, protocol.MaxPacketBufferSize, 700)
	for i, w := range want {
		p, err := c.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, w, p.data, "packet %d", i)
		p.buffer.Release()
	}
	require.Less(t, cb.msgs, segs)
}

// TestGRODisabledByEnv: QUIC_GO_DISABLE_GRO reads one datagram per
// message, as without GRO; the batch still arrives whole and in order.
func TestGRODisabledByEnv(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_GRO", "true")
	udpConn := newUDPConnLocalhost(t)
	c, err := newConn(udpConn, true)
	require.NoError(t, err)
	require.False(t, c.capabilities().GRO)
	want := gsoBatch(t, udpConn.LocalAddr(), 10, 1000, 10)
	for i, w := range want {
		p, err := c.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, w, p.data, "packet %d", i)
	}
}

// TestGSOBatchWithinLinuxLimits: a GSO batch is at most 64 segments
// (UDP_MAX_SEGMENTS) and fits one UDP datagram over IPv6.
func TestGSOBatchWithinLinuxLimits(t *testing.T) {
	require.LessOrEqual(t, int(protocol.MaxLargePacketBufferSize/protocol.MinInitialPacketSize), 64)
	require.LessOrEqual(t, int(protocol.MaxLargePacketBufferSize), 65535-8-40)
}

// TestSocketBuffers reports what the host gave.
func TestSocketBuffers(t *testing.T) {
	c := newUDPConnLocalhost(t)
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var want int
	require.NoError(t, rc.Control(func(fd uintptr) {
		want, _ = unix.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}))
	r, w, err := SocketBuffers(c)
	require.NoError(t, err)
	require.Equal(t, want, r)
	require.Positive(t, w)
}
