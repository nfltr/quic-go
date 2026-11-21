package quic

import (
	"testing"
	"testing/synctest"

	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/qlog"
	"github.com/nfltr/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestConnectionQueueHoldsGROReads: a connection busy for a while keeps
// every packet of eight reads with UDP GRO (batchSize messages, each up to
// 64 coalesced packets, Linux's UDP_GRO_CNT_MAX) instead of dropping them.
// With 256 a bulk receiver dropped a quarter of its packets at 0.2 ms RTT,
// each one resent after the time threshold (nfltr lane SPEEDWAIT).
func TestConnectionQueueHoldsGROReads(t *testing.T) {
	const groReads = 8 * 8 * 64 // reads x messages per read (Linux batchSize) x packets per message
	require.GreaterOrEqual(t, protocol.MaxConnUnprocessedPackets, groReads)
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
		for range groReads {
			tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})
		}
		synctest.Wait()
		require.Empty(t, eventRecorder.Events(qlog.PacketDropped{}))
		require.Equal(t, groReads, tc.conn.receivedPackets.Len())
	})
}
