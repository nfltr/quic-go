package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/quic-go"
	quicproxy "github.com/nfltr/quic-go/integrationtests/tools/proxy"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/qlog"
	"github.com/nfltr/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestInitialPacketSize(t *testing.T) {
	server := newUDPConnLocalhost(t)
	client := newUDPConnLocalhost(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		quic.Dial(ctx, client, server.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			InitialPacketSize: 1337,
		}))
	}()

	buf := make([]byte, 2000)
	n, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1337, n)

	cancel()
	<-done
}

func TestPathMTUDiscovery(t *testing.T) {
	rtt := scaleDuration(5 * time.Millisecond)
	const mtu = 1400

	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			InitialPacketSize:       1234,
			DisablePathMTUDiscovery: true,
			EnableDatagrams:         true,
		}),
	)
	require.NoError(t, err)
	defer ln.Close()

	serverErrChan := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverErrChan <- err
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverErrChan <- err
			return
		}
		defer str.Close()
		if _, err := io.Copy(str, str); err != nil {
			serverErrChan <- err
			return
		}
	}()

	var mx sync.Mutex
	var maxPacketSizeServer int
	var clientPacketSizes []int
	proxy := &quicproxy.Proxy{
		Conn:        newUDPConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
			if len(packet) > mtu {
				return true
			}
			mx.Lock()
			defer mx.Unlock()
			switch dir {
			case quicproxy.DirectionIncoming:
				clientPacketSizes = append(clientPacketSizes, len(packet))
			case quicproxy.DirectionOutgoing:
				if len(packet) > maxPacketSizeServer {
					maxPacketSizeServer = len(packet)
				}
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	// Make sure to use v4-only socket here.
	// We can't reliably set the DF bit on dual-stack sockets on older versions of macOS (before Sequoia).
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()

	var eventRecorder events.Recorder
	conn, err := tr.Dial(
		context.Background(),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			InitialPacketSize: protocol.MinInitialPacketSize,
			EnableDatagrams:   true,
			Tracer:            newTracer(&eventRecorder),
		}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	err = conn.SendDatagram(make([]byte, 2000))
	var datagramErr *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &datagramErr)
	initialMaxDatagramSize := datagramErr.MaxDatagramPayloadSize

	str, err := conn.OpenStream()
	require.NoError(t, err)

	clientErrChan := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(str)
		if err != nil {
			clientErrChan <- err
			return
		}
		if !bytes.Equal(data, PRDataLong) {
			clientErrChan <- fmt.Errorf("echoed data doesn't match: %x", data)
			return
		}
		clientErrChan <- nil
	}()

	_, err = str.Write(PRDataLong)
	require.NoError(t, err)
	str.Close()

	select {
	case err := <-clientErrChan:
		require.NoError(t, err)
	case err := <-serverErrChan:
		t.Fatalf("server error: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("timeout")
	}

	err = conn.SendDatagram(make([]byte, 2000))
	require.Error(t, err)
	require.ErrorAs(t, err, &datagramErr)
	finalMaxDatagramSize := datagramErr.MaxDatagramPayloadSize

	mx.Lock()
	defer mx.Unlock()
	require.NotEmpty(t, eventRecorder.Events(qlog.MTUUpdated{}))

	var mtus []int
	for _, ev := range eventRecorder.Events(qlog.MTUUpdated{}) {
		mtus = append(mtus, ev.(qlog.MTUUpdated).Value)
	}

	maxPacketSizeClient := mtus[len(mtus)-1]
	t.Logf("max client packet size: %d, MTU: %d", maxPacketSizeClient, mtu)
	t.Logf("max datagram size: initial: %d, final: %d", initialMaxDatagramSize, finalMaxDatagramSize)
	t.Logf("max server packet size: %d, MTU: %d", maxPacketSizeServer, mtu)

	require.GreaterOrEqual(t, maxPacketSizeClient, mtu-25)
	const maxDiff = 40 // this includes the 21 bytes for the short header, 16 bytes for the encryption tag, and framing overhead
	require.GreaterOrEqual(t, int(initialMaxDatagramSize), protocol.MinInitialPacketSize-maxDiff)
	require.GreaterOrEqual(t, int(finalMaxDatagramSize), maxPacketSizeClient-maxDiff)
	// MTU discovery was disabled on the server side
	require.Equal(t, 1234, maxPacketSizeServer)

	var numPacketsLargerThanDiscoveredMTU int
	for _, s := range clientPacketSizes {
		if s > maxPacketSizeClient {
			numPacketsLargerThanDiscoveredMTU++
		}
	}
	// The client shouldn't have sent any packets larger than the MTU it discovered,
	// except for at most one MTU probe packet.
	require.LessOrEqual(t, numPacketsLargerThanDiscoveredMTU, 1)
}

// TestJumboPackets: on a path with a large MTU (loopback), path MTU
// discovery reaches Config.MaxPacketSize above 1452 where both ends'
// Transports read such packets (a probe counts once the peer acked it,
// so it was read whole), and the bytes arrive intact; a peer with the
// zero value keeps 1452.
func TestJumboPackets(t *testing.T) {
	const jumbo = protocol.MaxJumboPacketSize
	for _, tc := range []struct {
		name       string
		serverSize uint16
		wantMin    int64
		wantMax    int64
	}{
		{"both jumbo", jumbo, jumbo - 100, jumbo},
		{"server default", 0, protocol.MaxPacketBufferSize - 20, protocol.MaxPacketBufferSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			str := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxPacketSize: tc.serverSize}
			defer str.Close()
			ln, err := str.Listen(getTLSConfig(), getQuicConfig(&quic.Config{MaxPacketSize: tc.serverSize}))
			require.NoError(t, err)
			defer ln.Close()

			var rec events.Recorder
			tr := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxPacketSize: jumbo}
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
			defer cancel()
			conn, err := tr.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{MaxPacketSize: jumbo, Tracer: newTracer(&rec)}))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			mtu := func() int64 {
				var m int64
				for _, ev := range rec.Events(qlog.MTUUpdated{}) {
					m = max(m, int64(ev.(qlog.MTUUpdated).Value))
				}
				return m
			}

			// Path MTU discovery probes every 5 RTTs: write until the
			// datagrams reach the size the ends allow (or the deadline).
			chunk := GeneratePRData(1 << 20)
			got := make(chan []byte, 1)
			go func() {
				sconn, err := ln.Accept(ctx)
				if err != nil {
					got <- nil
					return
				}
				str, err := sconn.AcceptStream(ctx)
				if err != nil {
					got <- nil
					return
				}
				b, _ := io.ReadAll(str)
				got <- b
			}()
			str2, err := conn.OpenStream()
			require.NoError(t, err)
			var sent []byte
			for mtu() < tc.wantMin && ctx.Err() == nil {
				_, err = str2.Write(chunk)
				require.NoError(t, err)
				sent = append(sent, chunk...)
			}
			require.NoError(t, str2.Close())
			require.True(t, bytes.Equal(sent, <-got), "bytes differ")
			m := mtu()
			require.GreaterOrEqual(t, m, tc.wantMin)
			require.LessOrEqual(t, m, tc.wantMax)
		})
	}
}
