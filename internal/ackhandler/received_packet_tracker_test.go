package ackhandler

import (
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"
	"github.com/nfltr/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketTrackerGenerateACKs(t *testing.T) {
	tracker := newReceivedPacketTracker()

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(3), protocol.ECNNon, true))
	ack := tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 3}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(4), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 4}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(1), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	// non-ack-eliciting packets don't trigger ACKs
	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(10), protocol.ECNNon, false))
	require.Nil(t, tracker.GetAckFrame())

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(11), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 11},
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
}

func TestAppDataReceivedPacketTrackerECN(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	require.NoError(t, tr.ReceivedPacket(0, protocol.ECT0, monotime.Now(), true))
	pn := protocol.PacketNumber(1)
	for range 2 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECT1, monotime.Now(), true))
		pn++
	}
	for range 3 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNCE, monotime.Now(), true))
		pn++
	}
	ack := tr.GetAckFrame(monotime.Now(), false)
	require.Equal(t, uint64(1), ack.ECT0)
	require.Equal(t, uint64(2), ack.ECT1)
	require.Equal(t, uint64(3), ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerAckEverySecondPacket(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	for p := protocol.PacketNumber(1); p <= 20; p++ {
		require.NoError(t, tr.ReceivedPacket(p, protocol.ECNNon, monotime.Now(), true))
		switch p % 2 {
		case 0:
			require.NotNil(t, tr.GetAckFrame(monotime.Now(), true))
		case 1:
			require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
		}
	}
}

func TestAppDataReceivedPacketTrackerAlarmTimeout(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, false))
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
	require.Zero(t, tr.GetAlarmTimeout())

	rcvTime := now.Add(10 * time.Millisecond)
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, rcvTime, true))
	require.Equal(t, rcvTime.Add(MaxAckDelay), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	// no timeout after the ACK has been dequeued
	require.NotNil(t, tr.GetAckFrame(monotime.Now(), false))
	require.Zero(t, tr.GetAlarmTimeout())
}

func TestAppDataReceivedPacketTrackerQueuesECNCE(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNCE, monotime.Now(), true))
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(1), ack.LargestAcked())
	require.EqualValues(t, 1, ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerMissingPackets(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))

	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
	ack := tr.GetAckFrame(now, true) // ACK: 0 and 5, missing: 1, 2, 3, 4
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 5}, {Smallest: 0, Largest: 0}}, ack.AckRanges)

	// now receive one of the missing packets
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	ack = tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 5, Largest: 5},
		{Smallest: 3, Largest: 3},
		{Smallest: 0, Largest: 0},
	}, ack.AckRanges)

	require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(8, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestAppDataReceivedPacketTrackerDelayTime(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(-1337*time.Millisecond), true))
	ack := tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, 1337*time.Millisecond, ack.DelayTime)

	// don't use a negative delay time
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(time.Hour), true))
	ack = tr.GetAckFrame(now, false)
	require.NotNil(t, ack)
	require.Zero(t, ack.DelayTime)
}

func TestAppDataReceivedPacketTrackerIgnoreBelow(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	tr.IgnoreBelow(4)
	// check that packets below 7 are considered duplicates
	require.True(t, tr.IsPotentiallyDuplicate(3))
	require.False(t, tr.IsPotentiallyDuplicate(4))

	for i := 5; i <= 10; i++ {
		require.NoError(t, tr.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, monotime.Now(), true))
	}
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 10}}, ack.AckRanges)

	tr.IgnoreBelow(7)

	require.NoError(t, tr.ReceivedPacket(11, protocol.ECNNon, monotime.Now(), true))
	require.NoError(t, tr.ReceivedPacket(12, protocol.ECNNon, monotime.Now(), true))
	ack = tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 7, Largest: 12}}, ack.AckRanges)

	// make sure that old packets are not accepted
	require.ErrorContains(t,
		tr.ReceivedPacket(4, protocol.ECNNon, monotime.Now(), true),
		"receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet 4",
	)
}

// TestAppDataReceivedPacketTrackerDecimation: past the first
// ackDecimationAfter ack-eliciting packets with an RTT measured, an ACK
// goes out every packetsBeforeAckDecimated packets, or a quarter of the
// min RTT after the first unacknowledged one; a missing packet is still
// acknowledged at once. Without an RTT: every second packet.
// Before an ACK_FREQUENCY frame the receiver is RFC 9000's: an ACK every
// second ack-eliciting packet, whatever the RTT (the fork's receiver-only
// decimation is gone: the peer asks for its ACK rate).
func TestAppDataReceivedPacketTrackerNoDecimationWithoutAckFrequency(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	now := monotime.Now()
	var k int
	for pn := range protocol.PacketNumber(400) {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		if tr.GetAckFrame(now, true) != nil {
			k++
		}
	}
	require.Equal(t, 200, k)
}

func ackFrequency(seq, threshold uint64, delay time.Duration, reordering protocol.PacketNumber) *wire.AckFrequencyFrame {
	return &wire.AckFrequencyFrame{SequenceNumber: seq, AckElicitingThreshold: threshold, RequestMaxAckDelay: delay, ReorderingThreshold: reordering}
}

// spec/AckFrequency.tla (github.com/nfltr/link) CountBound and
// AckWithinDelay: an ACK after more than the threshold, the alarm the
// requested delay after the oldest packet not yet acknowledged.
func TestAppDataReceivedPacketTrackerAckFrequencyThresholdAndDelay(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.SetAckFrequency(ackFrequency(0, 9, 5*time.Millisecond, 10))
	now := monotime.Now()
	for pn := range protocol.PacketNumber(9) {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now.Add(time.Duration(pn)*100*time.Microsecond), true))
		require.Nil(t, tr.GetAckFrame(now, true), "packet %d", pn)
	}
	// alarm-latest mutant: the alarm stays at the oldest packet's receipt.
	require.Equal(t, now.Add(5*time.Millisecond), tr.GetAlarmTimeout())
	require.NoError(t, tr.ReceivedPacket(9, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true), "the 10th packet")

	require.NoError(t, tr.ReceivedPacket(10, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now.Add(5*time.Millisecond-1), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(5*time.Millisecond), true))

	// A lower or equal sequence number is ignored.
	tr.SetAckFrequency(ackFrequency(0, 1, time.Millisecond, 1))
	for pn := protocol.PacketNumber(11); pn < 20; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true), "packet %d", pn)
	}
	tr.SetAckFrequency(ackFrequency(1, 0, time.Millisecond, 1))
	require.NoError(t, tr.ReceivedPacket(20, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true), "threshold 0: every packet")
}

// NoReorderAck (mutant threshold-ignored, the fork's wasMissing rule): a
// packet late by fewer than the reordering threshold forces no ACK.
func TestAppDataReceivedPacketTrackerAckFrequencyReorderingWithinThreshold(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.SetAckFrequency(ackFrequency(0, 9, 25*time.Millisecond, 10))
	now := monotime.Now()
	for pn := range protocol.PacketNumber(9) {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	require.NoError(t, tr.ReceivedPacket(10, protocol.ECNNon, now, true)) // 9 is late
	ack := tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(10), ack.LargestAcked())
	require.False(t, ack.AcksPacket(9))
	require.NoError(t, tr.ReceivedPacket(9, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true), "9 was reported missing, 1 place late: no immediate ACK")
	for pn := protocol.PacketNumber(11); pn < 19; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true), "packet %d", pn)
	}
}

// PromptLoss (mutant no-reorder-ack): a hole as deep as the reordering
// threshold, or a packet that many below the largest acknowledged, is
// acknowledged at once.
func TestAppDataReceivedPacketTrackerAckFrequencyDeepHole(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.SetAckFrequency(ackFrequency(0, 9, 25*time.Millisecond, 3))
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	for _, pn := range []protocol.PacketNumber{2, 3} {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true), "packet %d: hole 1 not yet 3 deep", pn)
	}
	require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, true))
	ack := tr.GetAckFrame(now, true)
	require.NotNil(t, ack, "hole 1 is 3 deep")
	require.False(t, ack.AcksPacket(1))
	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true), "hole 1 was reported")
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true), "1 arrived 3 or more below the largest acknowledged (4)")
}

// ImmediateAcked (mutant immediate-dropped).
func TestAppDataReceivedPacketTrackerImmediateAck(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.SetAckFrequency(ackFrequency(0, 9, 25*time.Millisecond, 10))
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	tr.ImmediateAck()
	require.NotNil(t, tr.GetAckFrame(now, true))
}
