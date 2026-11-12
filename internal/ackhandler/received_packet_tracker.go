package ackhandler

import (
	"fmt"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"
	"github.com/nfltr/quic-go/internal/wire"
)

const reorderingThreshold = 1

// The receivedPacketTracker tracks packets for the Initial and Handshake packet number space.
// Every received packet is acknowledged immediately.
type receivedPacketTracker struct {
	ect0, ect1, ecnce uint64

	packetHistory receivedPacketHistory

	lastAck   *wire.AckFrame
	hasNewAck bool // true as soon as we received an ack-eliciting new packet
}

func newReceivedPacketTracker() *receivedPacketTracker {
	return &receivedPacketTracker{packetHistory: *newReceivedPacketHistory()}
}

func (h *receivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, ackEliciting bool) error {
	if isNew := h.packetHistory.ReceivedPacket(pn); !isNew {
		return fmt.Errorf("receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet %d", pn)
	}

	//nolint:exhaustive // Only need to count ECT(0), ECT(1) and ECN-CE.
	switch ecn {
	case protocol.ECT0:
		h.ect0++
	case protocol.ECT1:
		h.ect1++
	case protocol.ECNCE:
		h.ecnce++
	}
	if !ackEliciting {
		return nil
	}
	h.hasNewAck = true
	return nil
}

func (h *receivedPacketTracker) GetAckFrame() *wire.AckFrame {
	if !h.hasNewAck {
		return nil
	}

	// This function always returns the same ACK frame struct, filled with the most recent values.
	ack := h.lastAck
	if ack == nil {
		ack = &wire.AckFrame{}
	}
	ack.Reset()
	ack.ECT0 = h.ect0
	ack.ECT1 = h.ect1
	ack.ECNCE = h.ecnce
	for r := range h.packetHistory.Backward() {
		ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: r.Start, Largest: r.End})
	}

	h.lastAck = ack
	h.hasNewAck = false
	return ack
}

func (h *receivedPacketTracker) IsPotentiallyDuplicate(pn protocol.PacketNumber) bool {
	return h.packetHistory.IsPotentiallyDuplicate(pn)
}

// MaxAckDelay is the maximum time by which we delay sending ACKs.
const MaxAckDelay = 25 * time.Millisecond

// number of ack-eliciting packets received before sending an ACK
const packetsBeforeAck = 2

// ACK decimation (nfltr fork): once ackDecimationAfter ack-eliciting
// packets have arrived and the RTT is known, send an ACK every
// packetsBeforeAckDecimated ack-eliciting packets, or a quarter of the min
// RTT (at least the timer granularity, at most max_ack_delay) after the
// first one not yet acknowledged, as Chromium's QUIC does. Every ACK
// costs a packet each way, and on hosts without UDP offloads (macOS) a
// send and a receive syscall and the wake-ups behind them: acking every
// second packet cost about a quarter of quic-go's CPU per MB of a bulk
// transfer on macOS. A missing packet, reordering and ECN-CE are still
// acknowledged at once (shouldQueueACK), so loss detection keeps its
// pace. Receiver-only: no wire change, max_ack_delay is still honoured.
// Guard: TestAppDataReceivedPacketTrackerDecimation; the gain:
// github.com/nfltr/link peerlink/quiclink BenchmarkBulkCPU.
const (
	ackDecimationAfter        = 100
	packetsBeforeAckDecimated = 10
)

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It waits until at least 2 packets were received before queueing an ACK, or until the max_ack_delay was reached.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved protocol.PacketNumber
	ignoreBelow     protocol.PacketNumber

	ackQueued bool // true if we need send a new ACK

	ackElicitingPacketsReceivedSinceLastAck int
	ackAlarm                                monotime.Time

	ackElicitingPacketsReceived int
	rttStats                    *utils.RTTStats // nil: no ACK decimation

	logger utils.Logger
}

func newAppDataReceivedPacketTracker(logger utils.Logger) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		logger:                logger,
	}
	return h
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
	}
	if !ackEliciting {
		return nil
	}
	h.ackElicitingPacketsReceivedSinceLastAck++
	h.ackElicitingPacketsReceived++
	isMissing := h.isMissing(pn)
	if !h.ackQueued && h.shouldQueueACK(pn, ecn, isMissing) {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
	}
	if !h.ackQueued && (h.ackAlarm.IsZero() || !h.decimating()) {
		// No ACK queued, but we'll need to acknowledge the packet after the ACK delay
		// (decimating: counted from the first packet not yet acknowledged).
		delay := h.ackDelay()
		h.ackAlarm = rcvTime.Add(delay)
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer to %s", delay)
		}
	}
	return nil
}

func (h *appDataReceivedPacketTracker) decimating() bool {
	return h.rttStats != nil && h.rttStats.HasMeasurement() && h.ackElicitingPacketsReceived > ackDecimationAfter
}

// ackDelay is how long an ack-eliciting packet may wait for its ACK.
func (h *appDataReceivedPacketTracker) ackDelay() time.Duration {
	if !h.decimating() {
		return MaxAckDelay
	}
	return min(max(h.rttStats.MinRTT()/4, protocol.TimerGranularity), MaxAckDelay)
}

// IgnoreBelow sets a lower limit for acknowledging packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *appDataReceivedPacketTracker) IgnoreBelow(pn protocol.PacketNumber) {
	if pn <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = pn
	h.packetHistory.DeleteBelow(pn)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %d.", pn)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *appDataReceivedPacketTracker) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	if h.lastAck == nil {
		return false
	}
	if h.largestObserved < reorderingThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		// the packet was already reported missing in the last ACK
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(pn protocol.PacketNumber, ecn protocol.ECN, wasMissing bool) bool {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if wasMissing {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing before.", pn)
		}
		return true
	}

	// send an ACK every 2 ack-eliciting packets (decimating: every 10)
	threshold := packetsBeforeAck
	if h.decimating() {
		threshold = packetsBeforeAckDecimated
	}
	if h.ackElicitingPacketsReceivedSinceLastAck >= threshold {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d packets were received after the last ACK (using initial threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, packetsBeforeAck)
		}
		return true
	}

	// queue an ACK if there are new missing packets to report
	if h.hasNewMissingPackets() {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return true
	}

	// queue an ACK if the packet was ECN-CE marked
	if ecn == protocol.ECNCE {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return true
	}
	return false
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
