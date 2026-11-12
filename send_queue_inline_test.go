package quic

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

// TestSendQueueWritesInline (nfltr fork): on darwin, with nothing queued,
// Send writes the packet itself (Run is not running here); once a packet
// waits in the queue, the next one queues behind it, so packets leave in
// order (GSO batches, Linux, never go inline). Elsewhere every packet queues.
func TestSendQueueWritesInline(t *testing.T) {
	for _, network := range []string{"udp4", "udp"} { // udp: a dual-stack socket sending to IPv4
		t.Run(network, func(t *testing.T) {
			rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer rx.Close()
			laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
			if network == "udp" {
				laddr = nil
			}
			tx, err := net.ListenUDP(network, laddr)
			require.NoError(t, err)
			defer tx.Close()
			raw, err := wrapConn(tx)
			require.NoError(t, err)
			q := newSendQueue(newSendConn(raw, rx.LocalAddr(), packetInfo{}, utils.DefaultLogger)).(*sendQueue)

			q.Send(getPacketWithContents([]byte("one")), 0, protocol.ECNNon)
			if runtime.GOOS != "darwin" {
				require.Len(t, q.queue, 1)
				return
			}
			require.Empty(t, q.queue, "written inline")
			require.NoError(t, rx.SetReadDeadline(time.Now().Add(5*time.Second)))
			b := make([]byte, 16)
			n, err := rx.Read(b)
			require.NoError(t, err)
			require.Equal(t, "one", string(b[:n]))

			// while Run writes a packet, the next ones queue behind it
			q.pending.Add(1)
			q.Send(getPacketWithContents([]byte("two")), 0, protocol.ECNNon)
			q.Send(getPacketWithContents([]byte("three")), 0, protocol.ECNNon)
			require.Len(t, q.queue, 2)
			q.pending.Add(-1)
			go q.Run()
			defer q.Close()
			for _, want := range []string{"two", "three"} {
				n, err := rx.Read(b)
				require.NoError(t, err)
				require.Equal(t, want, string(b[:n]))
			}
			require.Eventually(t, func() bool { return q.pending.Load() == 0 }, 5*time.Second, time.Millisecond)
			q.Send(getPacketWithContents([]byte("four")), 0, protocol.ECNNon)
			require.Empty(t, q.queue, "inline again once the queue is written")
			n, err = rx.Read(b)
			require.NoError(t, err)
			require.Equal(t, "four", string(b[:n]))
		})
	}
}
