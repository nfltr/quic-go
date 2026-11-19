package self_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// bottleneckRouter forwards packets to `to` through a FIFO drained at rate
// bits/s, tail-dropping a packet that would wait longer than queue: the
// shape of a rate-limited link (netem rate, a token bucket) in front of
// the receiver. Packets in the other direction pass unshaped.
type bottleneckRouter struct {
	simnet.PerfectRouter
	to    net.Addr
	rate  float64
	queue time.Duration

	mu       sync.Mutex
	nextFree time.Time
	dropped  int
}

func (r *bottleneckRouter) SendPacket(p simnet.Packet) error {
	if p.To.String() != r.to.String() {
		return r.PerfectRouter.SendPacket(p)
	}
	r.mu.Lock()
	now := time.Now()
	start := now
	if r.nextFree.After(now) {
		start = r.nextFree
	}
	if start.Sub(now) > r.queue {
		r.dropped++
		r.mu.Unlock()
		return nil
	}
	r.nextFree = start.Add(time.Duration(float64(len(p.Data)*8) / r.rate * float64(time.Second)))
	at := r.nextFree.Sub(now)
	r.mu.Unlock()
	time.AfterFunc(at, func() { r.PerfectRouter.SendPacket(p) })
	return nil
}

// TestBulkUploadFillsRateLimitedBottleneck: one stream's bulk upload over a
// 100 Mbit/s bottleneck with a 200 ms queue (send's netem matrix, lane
// QUICCAP) takes at least 85 % of the rate once past slow start, with the
// windows peerlink/quiclink gives the direct path (16 MiB per stream): 98 %
// at 95 and 150 ms. Congestion control, pacing and the receiver's ACK
// decimation all sit on this path. A 1 MiB stream window (the direct path's
// before relay client v0.23.2) gives 66 % and 42 %, with no packet dropped.
func TestBulkUploadFillsRateLimitedBottleneck(t *testing.T) {
	for _, rtt := range []time.Duration{95 * time.Millisecond, 150 * time.Millisecond} {
		t.Run(rtt.String(), func(t *testing.T) {
			testBulkUploadFillsBottleneck(t, rtt)
		})
	}
}

func testBulkUploadFillsBottleneck(t *testing.T, rtt time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 100e6
		const size = 64 << 20
		addrClient := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		addrServer := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &bottleneckRouter{to: addrServer, rate: rate, queue: 200 * time.Millisecond}
		n := &simnet.Simnet{Router: router}
		settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
		clientConn := n.NewEndpoint(addrClient, settings)
		serverConn := n.NewEndpoint(addrServer, settings)
		require.NoError(t, n.Start())
		defer n.Close()
		defer clientConn.Close()
		defer serverConn.Close()

		const window = 16 << 20
		qc := getQuicConfig(&quic.Config{
			InitialStreamReceiveWindow:     window,
			MaxStreamReceiveWindow:         window,
			InitialConnectionReceiveWindow: 16 * window,
			MaxConnectionReceiveWindow:     16 * window,
		})
		ln, err := quic.Listen(serverConn, getTLSConfig(), qc)
		require.NoError(t, err)
		defer ln.Close()

		type mark struct{ half, end time.Time }
		done := make(chan mark, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			str, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			var m mark
			buf := make([]byte, 64<<10)
			var got int
			for {
				k, err := str.Read(buf)
				got += k
				if m.half.IsZero() && got >= size/2 {
					m.half = time.Now()
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return
				}
			}
			m.end = time.Now()
			conn.CloseWithError(0, "")
			done <- m
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		conn, err := quic.Dial(ctx, clientConn, serverConn.LocalAddr(), getTLSClientConfig(), qc)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStream()
		require.NoError(t, err)
		chunk := make([]byte, 1<<20)
		for range size / len(chunk) {
			_, err := str.Write(chunk)
			require.NoError(t, err)
		}
		require.NoError(t, str.Close())
		m := <-done

		got := float64(size/2*8) / m.end.Sub(m.half).Seconds()
		router.mu.Lock()
		dropped := router.dropped
		router.mu.Unlock()
		t.Logf("rtt %s: second half at %.1f Mbit/s (%.0f%% of %.0f Mbit/s), %d packets dropped at the bottleneck",
			rtt, got/1e6, 100*got/rate, rate/1e6, dropped)
		require.GreaterOrEqual(t, got, 0.85*rate)
	})
}
