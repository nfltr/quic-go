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
// auto-tuning is the limit, as it should be.
func TestBulkUploadOnLongFatPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 1e9
		const rtt = 260 * time.Millisecond
		const size = 512 << 20
		const window = 16 << 20
		addrClient := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		addrServer := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &reorderRouter{to: addrServer, rate: rate, queue: 200 * time.Millisecond, maxLate: 10, rng: rand.New(rand.NewPCG(1, 2))}
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
			_, err := str.Write(chunk)
			require.NoError(t, err)
		}
		require.NoError(t, str.Close())
		m := <-done
		got := float64(size/2*8) / m.end.Sub(m.half).Seconds()
		cwnd := conn.ConnectionStats().CongestionWindow
		t.Logf("second half at %.1f Mbit/s (%.0f%%), %.1f MB in flight; congestion window %.1f MB", got/1e6, 100*got/rate, got/8*rtt.Seconds()/1e6, float64(cwnd)/1e6)
		t.Logf("BenchmarkLongFatPath 1 %.1f Mbit/s", got/1e6)
		require.GreaterOrEqual(t, got, 0.7*rate)
	})
}
