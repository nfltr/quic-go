package ackhandler

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"
	"github.com/nfltr/quic-go/internal/wire"
)

// inFlightPath drives a sentPacketHandler like a long fat path: inFlight
// packets between a send and its ACK (1 ms apart, so the RTT is inFlight
// ms), an ACK every ackEvery packets reporting the last 1.5 RTT of packets
// (as a receiver does until IgnoreBelow), every lossEvery-th packet lost
// and the packet threshold off (as after a spurious loss), so a hole
// waits 9/8 RTT for the time threshold.
type inFlightPath struct {
	sph                           *sentPacketHandler
	now                           monotime.Time
	inFlight, ackEvery, lossEvery int
	sent                          int
	next                          protocol.PacketNumber
	holes                         []protocol.PacketNumber // never delivered: lost or skipped, ascending
	ranges                        []wire.AckRange
	frames                        []StreamFrame
}

func newInFlightPath(inFlight, ackEvery, lossEvery int) *inFlightPath {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil,
		protocol.PerspectiveClient, nil, utils.DefaultLogger, Congestion{}).(*sentPacketHandler)
	now := monotime.Now()
	sph.DropPackets(protocol.EncryptionInitial, now)
	sph.DropPackets(protocol.EncryptionHandshake, now)
	sph.packetThresholdDisabled = true
	return &inFlightPath{sph: sph, now: now, inFlight: inFlight, ackEvery: ackEvery, lossEvery: lossEvery,
		frames: []StreamFrame{{Frame: &wire.StreamFrame{}}}}
}

func (p *inFlightPath) lost(pn protocol.PacketNumber) bool {
	return p.lossEvery > 0 && int(pn)%p.lossEvery == p.lossEvery-1
}

// step sends one packet and, every ackEvery packets, delivers the ACK for
// the packets sent inFlight packets ago. It returns whether it sent an ACK.
func (p *inFlightPath) step() bool {
	pn := p.sph.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	p.sph.SentPacket(p.now, pn, protocol.InvalidPacketNumber, p.frames, nil, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
	for x := p.next; x < pn; x++ { // skipped by the generator
		p.holes = append(p.holes, x)
	}
	if p.lost(pn) {
		p.holes = append(p.holes, pn)
	}
	p.next = pn + 1
	p.now = p.now.Add(time.Millisecond)
	p.sent++
	if p.sent <= p.inFlight || p.sent%p.ackEvery != 0 {
		return false
	}
	largest := pn - protocol.PacketNumber(p.inFlight)
	lowest := max(0, largest-protocol.PacketNumber(p.inFlight*3/2))
	// the ranges between the holes in [lowest, largest], highest first
	i, _ := slices.BinarySearch(p.holes, largest+1)
	p.ranges = p.ranges[:0]
	hi := largest
	for i--; len(p.ranges) < 64; i-- {
		lo := lowest
		if i >= 0 && p.holes[i] >= lowest {
			lo = p.holes[i] + 1
		}
		if lo <= hi {
			p.ranges = append(p.ranges, wire.AckRange{Smallest: lo, Largest: hi})
		}
		if i < 0 || p.holes[i] <= lowest {
			break
		}
		hi = p.holes[i] - 1
	}
	if len(p.ranges) == 0 {
		return false
	}
	if _, err := p.sph.ReceivedAck(&wire.AckFrame{AckRanges: p.ranges}, protocol.Encryption1RTT, p.now); err != nil {
		panic(err)
	}
	return true
}

// BenchmarkAckInFlight is the cost of one packet sent and acknowledged
// with 1k, 10k and 50k packets in flight (lane FORKLEFT: Helsinki ->
// Singapore holds ~45k on one connection): it must not grow with the
// packets in flight.
func BenchmarkAckInFlight(b *testing.B) {
	for _, n := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("inflight=%d", n), func(b *testing.B) {
			p := newInFlightPath(n, 10, 3000)
			for range 3 * n {
				p.step()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				p.step()
			}
		})
	}
}

// An ACK costs the packets it acknowledges or declares lost, not the
// packets in flight: 50x the packets in flight costs less than 5x per
// packet (lane FORKLEFT; before: 26x, the walk back to the previous
// packet in Remove and the walks from the oldest hole).
func TestAckCostIndependentOfInFlight(t *testing.T) {
	perPacket := func(n int) time.Duration {
		p := newInFlightPath(n, 10, 3000)
		for range 3 * n {
			p.step()
		}
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			for range 20000 {
				p.step()
			}
			best = min(best, time.Since(start)/20000)
		}
		return best
	}
	small, large := perPacket(1000), perPacket(50000)
	t.Logf("per packet: %s at 1k in flight, %s at 50k", small, large)
	if large > 5*small {
		t.Fatalf("per packet %s at 50k in flight, %s at 1k: grows with the packets in flight", large, small)
	}
}

// The loss walk stops at the first packet not lost: no packet left below
// the largest acknowledged is past the time or packet threshold, with
// losses and skipped packet numbers.
func TestDetectLostPacketsLeavesNoLostPacket(t *testing.T) {
	for _, pktThreshold := range []bool{true, false} {
		p := newInFlightPath(500, 7, 5)
		p.sph.packetThresholdDisabled = !pktThreshold
		for range 20000 {
			if !p.step() {
				continue
			}
			h := p.sph
			largest := h.appDataPackets.largestAcked
			lossDelay := max(max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT())*time.Duration(8+h.timeThresholdEighths)/8, protocol.TimerGranularity)
			for pn, pk := range h.hist.Packets() {
				if pn > largest {
					break
				}
				if !pk.SendTime.After(p.now.Add(-lossDelay)) {
					t.Fatalf("packet %d past the time threshold left in flight", pn)
				}
				if pktThreshold && h.hist.Difference(largest, pn) >= h.appDataPacketThreshold {
					t.Fatalf("packet %d past the packet threshold left in flight", pn)
				}
			}
		}
	}
}
