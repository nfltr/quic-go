package ackhandler

import (
	"fmt"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"
	"github.com/nfltr/quic-go/internal/wire"
)

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

// ackPolicy is when the 1-RTT receiver acknowledges (draft-ietf-quic-ack-frequency
// section 6): after more than threshold ack-eliciting packets, maxDelay
// after the oldest one not yet acknowledged, and at once for a hole
// reordering packets deep or a packet that many below the largest
// acknowledged (0: never for reordering). The default is RFC 9000's; the
// peer's ACK_FREQUENCY frame replaces it (SetAckFrequency). Every ACK costs
// a packet each way, and on hosts without UDP offloads (macOS) a send and a
// receive syscall: acking every second packet cost about a quarter of
// quic-go's CPU per MB of a bulk transfer, and acking every reordered
// packet a third of both ends' CPU on a reordering WAN path (nfltr
// docs/decisions/send-cpu-per-gib-2026-11-21.md). Model and guard:
// github.com/nfltr/link spec/AckFrequency.tla,
// TestAckFrequencyPolicyInvariants.
type ackPolicy struct {
	threshold  int
	maxDelay   time.Duration
	reordering protocol.PacketNumber
}

var defaultAckPolicy = ackPolicy{threshold: 1, maxDelay: MaxAckDelay, reordering: 1}

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

	policy    ackPolicy
	policySeq int64 // the largest ACK_FREQUENCY sequence number applied (-1: none)

	logger utils.Logger
}

func newAppDataReceivedPacketTracker(logger utils.Logger) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		policy:                defaultAckPolicy,
		policySeq:             -1,
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
	if !h.ackQueued && h.shouldQueueACK(pn, ecn) {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
	}
	if !h.ackQueued && h.ackAlarm.IsZero() {
		// No ACK queued: acknowledge the oldest packet not yet acknowledged
		// after the ACK delay.
		h.ackAlarm = rcvTime.Add(h.policy.maxDelay)
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer to %s", h.policy.maxDelay)
		}
	}
	return nil
}

// SetAckFrequency applies the peer's ACK_FREQUENCY frame, unless one with
// this or a larger sequence number was applied already. The connection
// checked its Requested Max Ack Delay against our min_ack_delay.
func (h *appDataReceivedPacketTracker) SetAckFrequency(f *wire.AckFrequencyFrame) {
	if int64(f.SequenceNumber) <= h.policySeq {
		return
	}
	h.policySeq = int64(f.SequenceNumber)
	old := h.policy
	h.policy = ackPolicy{
		threshold:  int(min(f.AckElicitingThreshold, 1<<20)),
		maxDelay:   f.RequestMaxAckDelay,
		reordering: f.ReorderingThreshold,
	}
	if h.ackElicitingPacketsReceivedSinceLastAck > h.policy.threshold {
		h.ackQueued = true
	}
	if !h.ackAlarm.IsZero() && h.policy.maxDelay < old.maxDelay {
		h.ackAlarm = h.ackAlarm.Add(h.policy.maxDelay - old.maxDelay)
	}
}

// ImmediateAck handles an IMMEDIATE_ACK frame: an ACK at once.
func (h *appDataReceivedPacketTracker) ImmediateAck() {
	h.ackQueued = true
	h.ackAlarm = 0
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

// hasNewMissingPackets says if a hole is now h.policy.reordering below the
// largest packet received and the last ACK did not report it that deep
// (draft-ietf-quic-ack-frequency section 6.2: Unreported Missing). Before
// the first ACK none: the 1-RTT packet numbers follow the handshake's in
// one space, so the numbers below the first 1-RTT packet look missing.
func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	r := h.policy.reordering
	if h.lastAck == nil || h.largestObserved < r {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - r)
	if highestMissing == protocol.InvalidPacketNumber || highestMissing < h.ignoreBelow {
		return false
	}
	return highestMissing+r > h.lastAck.LargestAcked()
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(pn protocol.PacketNumber, ecn protocol.ECN) bool {
	if h.ackElicitingPacketsReceivedSinceLastAck > h.policy.threshold {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because %d packets were received after the last ACK (threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, h.policy.threshold)
		}
		return true
	}
	if r := h.policy.reordering; r > 0 {
		// A packet r or more below the largest acknowledged: the peer may
		// have declared it lost.
		if h.lastAck != nil && pn+r <= h.lastAck.LargestAcked() {
			if h.logger.Debug() {
				h.logger.Debugf("\tQueueing ACK because packet %d arrived %d or more below the largest acknowledged.", pn, r)
			}
			return true
		}
		if h.hasNewMissingPackets() {
			h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
			return true
		}
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
