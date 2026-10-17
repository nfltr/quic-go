package ackhandler

import (
	"cmp"
	"iter"
	"slices"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/wire"
)

// maxTrackedLostPackets bounds the lost packets tracked to detect spurious losses.
// A loss event can declare a whole congestion window lost (e.g. when a path reorders a burst),
// and the congestion controller only undoes its cutback once every packet counted for it
// turns out to be a spurious loss: a lost packet that is no longer tracked can't.
const maxTrackedLostPackets = protocol.MaxCongestionWindowPackets

const shrinkLostPacketsAbove = 64

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
}

type lostPacketTracker struct {
	lostPackets []lostPacket
}

func newLostPacketTracker() *lostPacketTracker {
	return &lostPacketTracker{
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

// Add adds a lost packet.
// Packets are lost in the order they were sent, so they are usually added in ascending order.
func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time) {
	if len(t.lostPackets) == maxTrackedLostPackets {
		t.lostPackets = t.lostPackets[1:]
	}
	lp := lostPacket{PacketNumber: p, SendTime: sendTime}
	if n := len(t.lostPackets); n == 0 || t.lostPackets[n-1].PacketNumber < p {
		t.lostPackets = append(t.lostPackets, lp)
		return
	}
	i, found := t.search(p)
	if found {
		return
	}
	t.lostPackets = slices.Insert(t.lostPackets, i, lp)
}

func (t *lostPacketTracker) search(pn protocol.PacketNumber) (int, bool) {
	return slices.BinarySearchFunc(t.lostPackets, pn, func(p lostPacket, pn protocol.PacketNumber) int {
		return cmp.Compare(p.PacketNumber, pn)
	})
}

// Delete deletes a packet from the lost packet tracker.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	if i, found := t.search(pn); found {
		t.lostPackets = slices.Delete(t.lostPackets, i, i+1)
	}
}

// DeleteAll deletes packets from the lost packet tracker. pns must be sorted in ascending order.
func (t *lostPacketTracker) DeleteAll(pns []protocol.PacketNumber) {
	if len(pns) == 0 {
		return
	}
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		_, found := slices.BinarySearch(pns, p.PacketNumber)
		return found
	})
	t.maybeShrink()
}

// Acked iterates over the lost packets that ackRanges acknowledge, in ascending order.
// ackRanges are sorted in descending order, as in an ACK frame.
func (t *lostPacketTracker) Acked(ackRanges []wire.AckRange) iter.Seq2[protocol.PacketNumber, monotime.Time] {
	return func(yield func(protocol.PacketNumber, monotime.Time) bool) {
		var i int // the first lost packet not below the current ACK range
		for j := len(ackRanges) - 1; j >= 0 && i < len(t.lostPackets); j-- {
			r := ackRanges[j]
			if t.lostPackets[i].PacketNumber > r.Largest {
				continue
			}
			if r.Smallest > t.lostPackets[len(t.lostPackets)-1].PacketNumber {
				return
			}
			// Advance to the first lost packet not below the range: ACK ranges often lie between
			// adjacent lost packets, only skip ahead by binary search when that doesn't get there.
			for range 8 {
				if t.lostPackets[i].PacketNumber >= r.Smallest {
					break
				}
				i++
			}
			if t.lostPackets[i].PacketNumber < r.Smallest {
				k, _ := slices.BinarySearchFunc(t.lostPackets[i:], r.Smallest, func(p lostPacket, pn protocol.PacketNumber) int {
					return cmp.Compare(p.PacketNumber, pn)
				})
				i += k
			}
			for ; i < len(t.lostPackets) && t.lostPackets[i].PacketNumber <= r.Largest; i++ {
				if !yield(t.lostPackets[i].PacketNumber, t.lostPackets[i].SendTime) {
					return
				}
			}
		}
	}
}

func (t *lostPacketTracker) All() iter.Seq2[protocol.PacketNumber, monotime.Time] {
	return func(yield func(protocol.PacketNumber, monotime.Time) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p.SendTime) {
				return
			}
		}
	}
}

func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) {
	if len(t.lostPackets) == 0 {
		return
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
	t.maybeShrink()
}

func (t *lostPacketTracker) Reset() {
	t.lostPackets = t.lostPackets[:0]
	t.maybeShrink()
}

// maybeShrink releases a large backing array once no lost packet is tracked:
// after a loss event declared many packets lost, it would otherwise be kept for the connection's lifetime.
func (t *lostPacketTracker) maybeShrink() {
	if len(t.lostPackets) == 0 && cap(t.lostPackets) > shrinkLostPacketsAbove {
		t.lostPackets = make([]lostPacket, 0, 4)
	}
}
