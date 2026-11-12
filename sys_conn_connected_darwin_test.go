//go:build darwin

package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/testdata"
	"github.com/nfltr/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

// TestConnectedSendSconn: a send conn sends on the shared socket until
// connectThreshold packets, then on a socket of its own connected to the
// remote, from the same port; the remote's datagrams read on it reach
// the transport's handler; a remote address change and the connection's
// end close it (the end for good).
func TestConnectedSendSconn(t *testing.T) {
	for _, network := range []string{"udp4", "udp"} { // udp: a dual-stack socket sending to IPv4
		t.Run(network, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer peer.Close()
			tx, err := net.ListenUDP(network, nil)
			require.NoError(t, err)
			defer tx.Close()
			raw, err := wrapConn(tx)
			require.NoError(t, err)
			delivered := make(chan receivedPacket, 4)
			setConnectedDeliver(raw, func(p receivedPacket) { delivered <- p })
			c := newSendConn(raw, peer.LocalAddr(), packetInfo{}, utils.DefaultLogger)
			port := tx.LocalAddr().(*net.UDPAddr).Port

			require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
			b := make([]byte, 64)
			for i := range connectThreshold {
				require.Nil(t, c.connected.sock.Load(), "packet %d", i)
				require.NoError(t, c.Write([]byte("x"), 0, protocol.ECNNon))
				_, from, err := peer.ReadFromUDP(b)
				require.NoError(t, err)
				require.Equal(t, port, from.Port)
			}
			require.NotNil(t, c.connected.sock.Load())
			require.True(t, c.tryWrite([]byte("inline"), protocol.ECNNon))
			n, from, err := peer.ReadFromUDP(b)
			require.NoError(t, err)
			require.Equal(t, "inline", string(b[:n]))
			require.Equal(t, port, from.Port, "the connected socket sends from the shared port")

			_, err = peer.WriteToUDP([]byte("back"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			require.NoError(t, err)
			select {
			case p := <-delivered:
				require.Equal(t, "back", string(p.data))
				require.Equal(t, peer.LocalAddr().(*net.UDPAddr).Port, p.remoteAddr.(*net.UDPAddr).Port)
			case <-time.After(5 * time.Second):
				t.Fatal("the connected socket's datagram did not reach the handler")
			}

			c.ChangeRemoteAddr(peer.LocalAddr(), packetInfo{})
			require.Nil(t, c.connected.sock.Load())
			_, err = peer.WriteToUDP([]byte("shared"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			require.NoError(t, err)
			p, err := raw.ReadPacket()
			require.NoError(t, err)
			require.Equal(t, "shared", string(p.data), "after the reset the shared socket reads again")

			for range connectThreshold {
				require.NoError(t, c.Write([]byte("y"), 0, protocol.ECNNon))
			}
			require.NotNil(t, c.connected.sock.Load(), "reconnected after the reset")
			c.closeConnected()
			for range 2 * connectThreshold {
				require.NoError(t, c.Write([]byte("z"), 0, protocol.ECNNon))
			}
			require.Nil(t, c.connected.sock.Load(), "never again after the end")
		})
	}
}

// TestConnectedSendRefusedIsLoss: the ICMP error a connected socket
// reports for a datagram to a closed port is a lost packet, never an
// error or a junk packet, and the socket keeps reading.
func TestConnectedSendRefusedIsLoss(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer tx.Close()
	raw, err := wrapConn(tx)
	require.NoError(t, err)
	delivered := make(chan receivedPacket, 64)
	setConnectedDeliver(raw, func(p receivedPacket) { delivered <- p })
	c := newSendConn(raw, peerAddr, packetInfo{}, utils.DefaultLogger)
	c.connected.sent.Store(connectThreshold)
	require.NoError(t, c.Write([]byte("first"), 0, protocol.ECNNon))
	require.NotNil(t, c.connected.sock.Load())
	require.NoError(t, peer.Close())
	for range 5 {
		require.NoError(t, c.Write([]byte("lost"), 0, protocol.ECNNon))
		time.Sleep(5 * time.Millisecond) // the ICMP error comes back
	}
	require.NotNil(t, c.connected.sock.Load(), "still connected")
	peer, err = net.ListenUDP("udp4", peerAddr)
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, c.Write([]byte("again"), 0, protocol.ECNNon))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	b := make([]byte, 16)
	n, from, err := peer.ReadFromUDP(b)
	require.NoError(t, err)
	require.Equal(t, "again", string(b[:n]))
	_, err = peer.WriteToUDP([]byte("back"), from)
	require.NoError(t, err)
	select {
	case p := <-delivered:
		require.Equal(t, "back", string(p.data), "no stale packet first")
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop stopped")
	}
}

// TestConnectedSendClosedSocketFallsBack: a send racing a reset goes out
// on the shared socket, without an error.
func TestConnectedSendClosedSocketFallsBack(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer peer.Close()
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer tx.Close()
	raw, err := wrapConn(tx)
	require.NoError(t, err)
	setConnectedDeliver(raw, func(receivedPacket) {})
	c := newSendConn(raw, peer.LocalAddr(), packetInfo{}, utils.DefaultLogger)
	c.connected.sent.Store(connectThreshold)
	ai := c.remoteAddrInfo.Load()
	cs := c.connected.get(c, ai)
	require.NotNil(t, cs)
	require.NoError(t, cs.conn.Close()) // closed under the sender
	sent, err := c.connected.outcome(cs, cs.send([]byte("a"), nil, true))
	require.False(t, sent)
	require.NoError(t, err)
	require.NoError(t, c.Write([]byte("b"), 0, protocol.ECNNon), "the read loop dropped the closed socket")
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	b := make([]byte, 8)
	n, err := peer.Read(b)
	require.NoError(t, err)
	require.Equal(t, "b", string(b[:n]))
}

// TestConnectedSendPathErrorReconnects: a send that fails because the
// path is gone (the address the socket was connected from left the host)
// drops the connected socket, the packet goes out on the shared socket,
// and a new socket is connected after connectThreshold more packets.
func TestConnectedSendPathErrorReconnects(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer peer.Close()
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer tx.Close()
	raw, err := wrapConn(tx)
	require.NoError(t, err)
	setConnectedDeliver(raw, func(receivedPacket) {})
	c := newSendConn(raw, peer.LocalAddr(), packetInfo{}, utils.DefaultLogger)
	c.connected.sent.Store(connectThreshold)
	cs := c.connected.get(c, c.remoteAddrInfo.Load())
	require.NotNil(t, cs)
	for _, e := range []error{syscall.EADDRNOTAVAIL, syscall.ENETUNREACH} {
		sent, err := c.connected.outcome(cs, e)
		require.False(t, sent, "%v: send it on the shared socket", e)
		require.NoError(t, err)
		require.Nil(t, c.connected.sock.Load())
		require.False(t, c.connected.failed.Load(), "count again")
		for range connectThreshold {
			require.NoError(t, c.Write([]byte("x"), 0, protocol.ECNNon))
		}
		cs = c.connected.sock.Load()
		require.NotNil(t, cs, "reconnected")
	}
}

// TestConnectedSendTransfer: a QUIC transfer on loopback moves its bulk
// on connected sockets at both ends, and they close with the connection.
func TestConnectedSendTransfer(t *testing.T) {
	for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), nil} { // nil: dual-stack wildcard sockets
		srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		require.NoError(t, err)
		defer srvConn.Close()
		cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		require.NoError(t, err)
		defer cliConn.Close()
		srvTr := &Transport{Conn: srvConn}
		defer srvTr.Close()
		cliTr := &Transport{Conn: cliConn}
		defer cliTr.Close()
		tc := testdata.GetTLSConfig()
		tc.NextProtos = []string{"quic-go-test"}
		ln, err := srvTr.Listen(tc, nil)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		srvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srvConn.LocalAddr().(*net.UDPAddr).Port}
		cli, err := cliTr.Dial(ctx, srvAddr, &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: []string{"quic-go-test"}}, nil)
		require.NoError(t, err)
		srv, err := ln.Accept(ctx)
		require.NoError(t, err)
		const size = 4 << 20
		go func() {
			s, err := cli.OpenStream()
			if err != nil {
				return
			}
			_, _ = s.Write(make([]byte, size))
			_ = s.Close()
		}()
		s, err := srv.AcceptStream(ctx)
		require.NoError(t, err)
		n, err := io.Copy(io.Discard, s)
		require.NoError(t, err)
		require.EqualValues(t, size, n)
		cliSend, srvSend := cli.conn.(*sconn), srv.conn.(*sconn)
		require.NotNil(t, cliSend.connected.sock.Load(), "client")
		require.NotNil(t, srvSend.connected.sock.Load(), "server (acknowledgments)")
		require.NoError(t, cli.CloseWithError(0, ""))
		<-srv.Context().Done()
		require.Eventually(t, func() bool {
			return cliSend.connected.sock.Load() == nil && srvSend.connected.sock.Load() == nil
		}, 5*time.Second, 10*time.Millisecond)
		_ = ln.Close()
	}
}
