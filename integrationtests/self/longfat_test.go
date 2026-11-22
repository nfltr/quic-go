package self_test

import (
	"context"
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// TestBulkUploadOnLongFatPath: one stream over a clean 1 Gbit/s, 260 ms RTT
// path (BDP 32.5 MB, Helsinki -> Singapore, lane LONGFAT) with nfltr's
// direct-path windows (16 MiB per stream, auto-tuned up to 64 MiB). The
// congestion window's cap of 10,000 packets (12.8 MB of these 1280-byte
// packets) held one connection at 0.37 Gbit/s here and 0.35 on the real
// path, however large the windows; at 65,536 packets the stream windows'
// auto-tuning is the limit, as it should be. burst-loss: the same path
// with a 10 ms queue, 30 % of packets up to 10 places late and 0.02 %
// lost: BBR's startup overflows the queue and drops thousands of packets
// at once, and the receiver's 1000-gap limit closed the connection ("too
// many gaps in received data": the direct path lost, Helsinki ->
// Singapore); it must deliver every byte.
func TestBulkUploadOnLongFatPath(t *testing.T) {
	for _, c := range []struct {
		name         string
		queue        time.Duration
		reorder, min float64
		loss         float64
	}{
		{"clean", 200 * time.Millisecond, 0, 0.7, 0},
		{"burst-loss", 10 * time.Millisecond, 0.3, 0.2, 0.0002},
	} {
		t.Run(c.name, func(t *testing.T) { testBulkUploadLongFat(t, c.queue, c.reorder, c.loss, c.min) })
	}
}

func testBulkUploadLongFat(t *testing.T, queue time.Duration, reorder, loss, min float64) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 1e9
		const rtt = 260 * time.Millisecond
		const size = 512 << 20
		const window = 16 << 20
		addrClient := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		addrServer := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &reorderRouter{to: addrServer, rate: rate, queue: queue, maxLate: 10, reorder: reorder, loss: loss, rng: rand.New(rand.NewPCG(1, 2))}
		n := &simnet.Simnet{Router: router}
		settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
		clientConn := n.NewEndpoint(addrClient, settings)
		serverConn := n.NewEndpoint(addrServer, settings)
		require.NoError(t, n.Start())
		defer n.Close()
		defer clientConn.Close()
		defer serverConn.Close()
		qc := getQuicConfig(&quic.Config{
			InitialStreamReceiveWindow:     window,
			MaxStreamReceiveWindow:         4 * window,
			InitialConnectionReceiveWindow: 16 * window,
			MaxConnectionReceiveWindow:     16 * window,
			CongestionControl:              quic.CongestionControlBBR,
			AckFrequency:                   quiclinkAcks,
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
					t.Errorf("read after %d bytes: %v", got, err)
					close(done)
					return
				}
			}
			m.end = time.Now()
			conn.CloseWithError(0, "")
			done <- m
		}()
		conn, err := quic.Dial(context.Background(), clientConn, serverConn.LocalAddr(), getTLSClientConfig(), qc)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStream()
		require.NoError(t, err)
		chunk := make([]byte, 1<<20)
		for range size / len(chunk) {
			if _, err := str.Write(chunk); err != nil {
				break
			}
		}
		_ = str.Close()
		m, ok := <-done
		if !ok {
			return
		}
		got := float64(size/2*8) / m.end.Sub(m.half).Seconds()
		cwnd := conn.ConnectionStats().CongestionWindow
		t.Logf("second half at %.1f Mbit/s (%.0f%%), %.1f MB in flight; congestion window %.1f MB", got/1e6, 100*got/rate, got/8*rtt.Seconds()/1e6, float64(cwnd)/1e6)
		t.Logf("BenchmarkLongFatPath/%s 1 %.1f Mbit/s", t.Name(), got/1e6)
		require.GreaterOrEqual(t, got, min*rate)
	})
}
