package self_test

import (
	"context"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// reorderRouter is a bottleneckRouter whose link also reorders and loses:
// a packet leaving the FIFO is, with probability reorder, held for 1 to
// maxLate packet times (so up to maxLate later packets overtake it), and
// is lost with probability loss. That is the Helsinki -> Singapore path
// lane CROSSCLOUD measured: 29 % of datagrams late, up to 10 places,
// 0.04-0.06 % lost.
type reorderRouter struct {
	simnet.PerfectRouter
	to      net.Addr
	rate    float64
	queue   time.Duration
	reorder float64
	maxLate int
	loss    float64

	mu       sync.Mutex
	rng      *rand.Rand
	nextFree time.Time
	dropped  int
}

func (r *reorderRouter) SendPacket(p simnet.Packet) error {
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
	pktTime := time.Duration(float64(len(p.Data)*8) / r.rate * float64(time.Second))
	r.nextFree = start.Add(pktTime)
	at := r.nextFree.Sub(now)
	if r.rng.Float64() < r.loss {
		r.mu.Unlock()
		return nil
	}
	if r.rng.Float64() < r.reorder {
		at += time.Duration(1+r.rng.IntN(r.maxLate)) * pktTime
	}
	r.mu.Unlock()
	time.AfterFunc(at, func() { r.PerfectRouter.SendPacket(p) })
	return nil
}

// reorderSeed varies the router's random choices between runs (-count N).
var reorderSeed atomic.Uint64

type reorderCase struct {
	name    string
	cc      quic.CongestionControl
	reorder float64
	loss    float64
	// min is the second half's rate the case must reach, as a fraction of the
	// bottleneck's (0: report only).
	min float64
}

// TestBulkUploadOnReorderingPath: one stream's bulk upload over a 300 Mbit/s,
// 260 ms RTT bottleneck that reorders 30 % of packets by up to 10 places and
// loses 0.05 % of them, the Helsinki -> Singapore path of lane CROSSCLOUD,
// with nfltr's direct-path windows (16 MiB per stream).
//
// Reordering costs nothing: the receiver ACKs each out-of-order packet at
// once, and when those ACK-only packets were charged to its pacer it stayed
// pacing-limited, sent only ACKs and held back MAX_STREAM_DATA: 70 % with
// NewReno, 62 % with BBR. Random loss is NewReno's limit: its window falls
// to about 130 packets and grows one packet per RTT, 1 % of the rate
// (reported, not asserted); BBR keeps at least half of it (60-70 %). The rest is the
// window: a lost packet's hole holds the stream for an RTT, and 16 MiB is
// less than twice the BDP (32 MiB reaches 95 %).
func TestBulkUploadOnReorderingPath(t *testing.T) {
	reno, bbr := quic.CongestionControlReno, quic.CongestionControlBBR
	for _, c := range []reorderCase{
		{"reno/clean", reno, 0, 0, 0.85},
		{"reno/reorder", reno, 0.3, 0, 0.85},
		{"reno/loss", reno, 0, 0.0005, 0},
		{"reno/reorder+loss", reno, 0.3, 0.0005, 0},
		{"bbr/clean", bbr, 0, 0, 0.85},
		{"bbr/reorder", bbr, 0.3, 0, 0.85},
		{"bbr/loss", bbr, 0, 0.0005, 0.5},
		{"bbr/reorder+loss", bbr, 0.3, 0.0005, 0.5},
	} {
		t.Run(c.name, func(t *testing.T) {
			testBulkUploadReorder(t, c)
		})
	}
}

func testBulkUploadReorder(t *testing.T, c reorderCase) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 300e6
		const rtt = 260 * time.Millisecond
		const size = 256 << 20
		addrClient := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		addrServer := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &reorderRouter{
			to: addrServer, rate: rate, queue: 200 * time.Millisecond,
			reorder: c.reorder, maxLate: 10, loss: c.loss, rng: rand.New(rand.NewPCG(reorderSeed.Add(1), 2)),
		}
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
			CongestionControl:              c.cc,
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Hour)
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
		st := conn.ConnectionStats()

		got := float64(size/2*8) / m.end.Sub(m.half).Seconds()
		router.mu.Lock()
		dropped := router.dropped
		router.mu.Unlock()
		t.Logf("second half at %.1f Mbit/s (%.0f%%); %d of %d packets lost (%d at the queue)",
			got/1e6, 100*got/rate, st.PacketsLost, st.PacketsSent, dropped)
		// benchstat-readable: go test -run TestBulkUploadOnReorderingPath -v -count 6 | sed -n 's/^ *reorder_test.go:[0-9]*: //p' | grep ^Benchmark
		t.Logf("BenchmarkReorderingPath/%s 1 %.1f Mbit/s", c.name, got/1e6)
		require.GreaterOrEqual(t, got, c.min*rate)
	})
}
