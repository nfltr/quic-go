package ackhandler

import (
	"fmt"
	"iter"
	"slices"

	"github.com/nfltr/quic-go/internal/protocol"
)

const maxSkippedPackets = 4

type sentPacketHistory struct {
	// packets holds a slot per packet number from firstPacketNumber,
	// nil once acknowledged, declared lost or skipped. skip[i] (i a nil
	// slot) is a distance to a later slot with every slot between nil,
	// shortened as it is followed (path compression), so walking the
	// packets costs the packets left, not the slots: with ~45k packets
	// in flight on a long fat path an ACK walked every slot from the
	// oldest hole (lane FORKLEFT, BenchmarkAckInFlight).
	packets          []*packet
	skip             []uint32
	pathProbePackets []packetWithPacketNumber
	skippedPackets   []protocol.PacketNumber

	numOutstanding int

	firstPacketNumber   protocol.PacketNumber
	highestPacketNumber protocol.PacketNumber
}

func newSentPacketHistory() *sentPacketHistory {
	return &sentPacketHistory{
		packets:             make([]*packet, 0, 32),
		skip:                make([]uint32, 0, 32),
		skippedPackets:      make([]protocol.PacketNumber, 0, maxSkippedPackets),
		highestPacketNumber: protocol.InvalidPacketNumber,
		firstPacketNumber:   protocol.InvalidPacketNumber,
	}
}

func (h *sentPacketHistory) checkPacketNumberUse(pn protocol.PacketNumber) {
	if h.highestPacketNumber != protocol.InvalidPacketNumber {
		if pn <= h.highestPacketNumber {
			panic("non-increasing packet number use")
		}
	}
	if len(h.packets) > 0 {
		for range pn - h.highestPacketNumber - 1 {
			h.packets = append(h.packets, nil)
			h.skip = append(h.skip, 1)
		}
	}
	h.highestPacketNumber = pn
	if len(h.packets) == 0 {
		h.firstPacketNumber = pn
	}
}

func (h *sentPacketHistory) SkippedPacket(pn protocol.PacketNumber) {
	if len(h.skippedPackets) == maxSkippedPackets {
		h.skippedPackets = slices.Delete(h.skippedPackets, 0, 1)
	}
	h.skippedPackets = append(h.skippedPackets, pn)
}

func (h *sentPacketHistory) SentPacket(pn protocol.PacketNumber, p *packet) {
	h.checkPacketNumberUse(pn)
	h.packets = append(h.packets, p)
	h.skip = append(h.skip, 0)
	if p.Outstanding() {
		h.numOutstanding++
	}
}

func (h *sentPacketHistory) SentPathProbePacket(pn protocol.PacketNumber, p *packet) {
	h.checkPacketNumberUse(pn)
	h.packets = append(h.packets, &packet{EncryptionLevel: p.EncryptionLevel, isPathProbePacket: true})
	h.skip = append(h.skip, 0)
	h.pathProbePackets = append(h.pathProbePackets, packetWithPacketNumber{PacketNumber: pn, packet: p})
}

// next returns the first slot from i that holds a packet (len(h.packets)
// if none).
func (h *sentPacketHistory) next(i int) int {
	j := i
	for j < len(h.packets) && h.packets[j] == nil {
		j += int(h.skip[j])
	}
	for k := i; k < j; { // every slot from i to j is nil: point them at j
		n := k + int(h.skip[k])
		h.skip[k] = uint32(j - k)
		k = n
	}
	return j
}

// clear empties slot idx.
func (h *sentPacketHistory) clear(idx int) {
	h.packets[idx] = nil
	h.skip[idx] = 1
}

// Packets yields the packets in packet number order. The yield function
// may remove the packet it gets (Remove, DeclareLost).
func (h *sentPacketHistory) Packets() iter.Seq2[protocol.PacketNumber, *packet] {
	return h.PacketsFrom(0)
}

// PacketsFrom is Packets from packet number pn on.
func (h *sentPacketHistory) PacketsFrom(pn protocol.PacketNumber) iter.Seq2[protocol.PacketNumber, *packet] {
	return func(yield func(protocol.PacketNumber, *packet) bool) {
		for len(h.packets) > 0 {
			// h.firstPacketNumber moves on when the yield function removes the first packet
			pn = max(pn, h.firstPacketNumber)
			idx := int(pn - h.firstPacketNumber)
			if idx >= len(h.packets) {
				return
			}
			if idx = h.next(idx); idx == len(h.packets) {
				return
			}
			pn = h.firstPacketNumber + protocol.PacketNumber(idx)
			if !yield(pn, h.packets[idx]) {
				return
			}
			pn++
		}
	}
}

func (h *sentPacketHistory) PathProbes() iter.Seq2[protocol.PacketNumber, *packet] {
	return func(yield func(protocol.PacketNumber, *packet) bool) {
		for _, p := range h.pathProbePackets {
			if !yield(p.PacketNumber, p.packet) {
				return
			}
		}
	}
}

// FirstOutstanding returns the first outstanding packet in the given packet number space.
func (h *sentPacketHistory) FirstOutstanding(space protocol.PacketNumberSpace) (protocol.PacketNumber, *packet) {
	if !h.HasOutstandingPackets() {
		return protocol.InvalidPacketNumber, nil
	}
	for pn, p := range h.Packets() {
		if p.Outstanding() && p.EncryptionLevel.PacketNumberSpace() == space {
			return pn, p
		}
	}
	return protocol.InvalidPacketNumber, nil
}

// FirstOutstandingPathProbe returns the first outstanding path probe packet
func (h *sentPacketHistory) FirstOutstandingPathProbe() (protocol.PacketNumber, *packet) {
	if len(h.pathProbePackets) == 0 {
		return protocol.InvalidPacketNumber, nil
	}
	return h.pathProbePackets[0].PacketNumber, h.pathProbePackets[0].packet
}

func (h *sentPacketHistory) SkippedPackets() iter.Seq[protocol.PacketNumber] {
	return func(yield func(protocol.PacketNumber) bool) {
		for _, p := range h.skippedPackets {
			if !yield(p) {
				return
			}
		}
	}
}

func (h *sentPacketHistory) Len() int {
	return len(h.packets)
}

func (h *sentPacketHistory) NumOutstanding() int {
	return h.numOutstanding
}

// Remove removes a packet from the sent packet history.
// It must not be used for skipped packet numbers.
func (h *sentPacketHistory) Remove(pn protocol.PacketNumber) error {
	idx, ok := h.getIndex(pn)
	if !ok {
		return fmt.Errorf("packet %d not found in sent packet history", pn)
	}
	p := h.packets[idx]
	if p.Outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.clear(idx)
	// h.packets[0] always holds a packet: only the first one leaves nil
	// slots at the start (lane FORKLEFT: a walk back to the previous
	// packet cost every slot acknowledged since the oldest hole)
	if idx == 0 {
		h.cleanupStart()
	}
	if len(h.packets) > 0 && h.packets[0] == nil {
		panic("cleanup failed")
	}
	return nil
}

// RemovePathProbe removes a path probe packet.
// It scales O(N), but that's ok, since we don't expect to send many path probe packets.
// It is not valid to call this function in IteratePathProbes.
func (h *sentPacketHistory) RemovePathProbe(pn protocol.PacketNumber) *packet {
	var packetToDelete *packet
	idx := -1
	for i, p := range h.pathProbePackets {
		if p.PacketNumber == pn {
			packetToDelete = p.packet
			idx = i
			break
		}
	}
	if idx != -1 {
		// don't use slices.Delete, because it zeros the deleted element
		copy(h.pathProbePackets[idx:], h.pathProbePackets[idx+1:])
		h.pathProbePackets = h.pathProbePackets[:len(h.pathProbePackets)-1]
	}
	return packetToDelete
}

// getIndex gets the index of packet p in the packets slice.
func (h *sentPacketHistory) getIndex(p protocol.PacketNumber) (int, bool) {
	if len(h.packets) == 0 {
		return 0, false
	}
	if p < h.firstPacketNumber {
		return 0, false
	}
	index := int(p - h.firstPacketNumber)
	if index > len(h.packets)-1 {
		return 0, false
	}
	return index, true
}

func (h *sentPacketHistory) HasOutstandingPackets() bool {
	return h.numOutstanding > 0
}

func (h *sentPacketHistory) FirstPacketNumber() protocol.PacketNumber {
	return h.firstPacketNumber
}

func (h *sentPacketHistory) HasOutstandingPathProbes() bool {
	return len(h.pathProbePackets) > 0
}

// delete all nil entries at the beginning of the packets slice
func (h *sentPacketHistory) cleanupStart() {
	if i := h.next(0); i < len(h.packets) {
		h.packets = h.packets[i:]
		h.skip = h.skip[i:]
		h.firstPacketNumber += protocol.PacketNumber(i)
		return
	}
	h.packets = h.packets[:0]
	h.skip = h.skip[:0]
	h.firstPacketNumber = protocol.InvalidPacketNumber
}

func (h *sentPacketHistory) DeclareLost(pn protocol.PacketNumber) {
	idx, ok := h.getIndex(pn)
	if !ok {
		return
	}
	p := h.packets[idx]
	if p.Outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.clear(idx)
	if idx == 0 {
		h.cleanupStart()
	}
}

// Difference returns the difference between two packet numbers a and b (a - b),
// taking into account any skipped packet numbers between them.
//
// Note that old skipped packets are garbage collected at some point,
// so this function is not guaranteed to return the correct result after a while.
func (h *sentPacketHistory) Difference(a, b protocol.PacketNumber) protocol.PacketNumber {
	diff := a - b
	if len(h.skippedPackets) == 0 {
		return diff
	}
	if a < h.skippedPackets[0] || b > h.skippedPackets[len(h.skippedPackets)-1] {
		return diff
	}
	for _, p := range h.skippedPackets {
		if p > b && p < a {
			diff--
		}
	}
	return diff
}
