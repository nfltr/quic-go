package ackhandler

import (
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker()

	start := monotime.Now()
	want := make(map[protocol.PacketNumber]monotime.Time, maxTrackedLostPackets)
	for i := range maxTrackedLostPackets {
		pn := protocol.PacketNumber(i + 1)
		sendTime := start.Add(time.Duration(i))
		lt.Add(pn, sendTime)
		want[pn] = sendTime
	}
	require.Equal(t, want, maps.Collect(lt.All()))

	// Lose one more packet. The first one should be removed.
	lt.Add(maxTrackedLostPackets+1, start.Add(time.Duration(maxTrackedLostPackets)))
	delete(want, 1)
	want[maxTrackedLostPackets+1] = start.Add(time.Duration(maxTrackedLostPackets))
	require.Equal(t, want, maps.Collect(lt.All()))

	lt.Delete(5)
	lt.Delete(10)
	delete(want, 5)
	delete(want, 10)
	require.Equal(t, want, maps.Collect(lt.All()))

	lt.Reset()
	require.Empty(t, maps.Collect(lt.All()))
	lt.Add(42, start)
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{42: start}, maps.Collect(lt.All()))
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker()

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for pn := range lt.All() {
			pns = append(pns, pn)
		}
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start)
	lt.Add(5, start.Add(time.Second))
	lt.Add(8, start.Add(2*time.Second))
	lt.Add(10, start.Add(3*time.Second))

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Hour))
	require.Empty(t, trackedPackets(lt))
}

func TestLostPacketTrackerAcked(t *testing.T) {
	lt := newLostPacketTracker()
	start := monotime.Now()
	for _, pn := range []protocol.PacketNumber{2, 4, 6, 10, 12} {
		lt.Add(pn, start.Add(time.Duration(pn)))
	}
	// packets are usually lost in ascending order, but not necessarily
	lt.Add(8, start.Add(8))
	lt.Add(4, start.Add(4)) // duplicate

	// acked takes ACK ranges in ascending order, for readability
	acked := func(ranges ...wire.AckRange) []protocol.PacketNumber {
		slices.Reverse(ranges)
		var pns []protocol.PacketNumber
		for pn, sendTime := range lt.Acked(ranges) {
			require.Equal(t, start.Add(time.Duration(pn)), sendTime)
			pns = append(pns, pn)
		}
		return pns
	}
	require.Equal(t, []protocol.PacketNumber{2, 4, 6, 8, 10, 12}, acked(wire.AckRange{Smallest: 0, Largest: 100}))
	require.Equal(t, []protocol.PacketNumber{4, 6, 8}, acked(wire.AckRange{Smallest: 3, Largest: 8}))
	require.Equal(t, []protocol.PacketNumber{6}, acked(wire.AckRange{Smallest: 6, Largest: 6}))
	require.Empty(t, acked(wire.AckRange{Smallest: 13, Largest: 100}))
	require.Empty(t, acked(wire.AckRange{Smallest: 0, Largest: 1}))
	require.Empty(t, acked(wire.AckRange{Smallest: 7, Largest: 7}))
	require.Empty(t, acked())
	// ranges between the lost packets, and some acknowledging them
	require.Empty(t, acked(wire.AckRange{Smallest: 1, Largest: 1}, wire.AckRange{Smallest: 3, Largest: 3}, wire.AckRange{Smallest: 9, Largest: 9}))
	require.Equal(t,
		[]protocol.PacketNumber{2, 8, 10, 12},
		acked(wire.AckRange{Smallest: 1, Largest: 2}, wire.AckRange{Smallest: 5, Largest: 5}, wire.AckRange{Smallest: 7, Largest: 10}, wire.AckRange{Smallest: 12, Largest: 20}),
	)
	require.Equal(t,
		[]protocol.PacketNumber{4, 12},
		acked(wire.AckRange{Smallest: 0, Largest: 1}, wire.AckRange{Smallest: 4, Largest: 4}, wire.AckRange{Smallest: 11, Largest: 13}),
	)

	lt.DeleteAll([]protocol.PacketNumber{4, 7, 8, 12})
	require.Equal(t, []protocol.PacketNumber{2, 6, 10}, acked(wire.AckRange{Smallest: 0, Largest: 100}))
	lt.Delete(6)
	lt.Delete(7)
	require.Equal(t, []protocol.PacketNumber{2, 10}, acked(wire.AckRange{Smallest: 0, Largest: 100}))
}

func TestLostPacketTrackerReleasesMemory(t *testing.T) {
	lt := newLostPacketTracker()
	start := monotime.Now()
	for i := range 1000 {
		lt.Add(protocol.PacketNumber(i), start.Add(time.Duration(i)))
	}
	require.Greater(t, cap(lt.lostPackets), shrinkLostPacketsAbove)
	lt.DeleteBefore(start.Add(500))
	require.Greater(t, cap(lt.lostPackets), shrinkLostPacketsAbove) // still in use
	lt.DeleteBefore(start.Add(time.Hour))
	require.LessOrEqual(t, cap(lt.lostPackets), shrinkLostPacketsAbove)

	for i := range 1000 {
		lt.Add(protocol.PacketNumber(i), start.Add(time.Duration(i)))
	}
	pns := make([]protocol.PacketNumber, 1000)
	for i := range pns {
		pns[i] = protocol.PacketNumber(i)
	}
	lt.DeleteAll(pns)
	require.LessOrEqual(t, cap(lt.lostPackets), shrinkLostPacketsAbove)
}

func TestLostPacketTrackerAckedRandomized(t *testing.T) {
	start := monotime.Now()
	for range 2000 {
		lt := newLostPacketTracker()
		lost := make(map[protocol.PacketNumber]bool)
		var pn protocol.PacketNumber
		for range rand.IntN(100) {
			pn += protocol.PacketNumber(1 + rand.IntN(20))
			lt.Add(pn, start.Add(time.Duration(pn)))
			lost[pn] = true
		}
		// ACK ranges in descending order, with gaps of at least one packet
		var ranges []wire.AckRange
		largest := pn + protocol.PacketNumber(rand.IntN(50))
		for range 1 + rand.IntN(40) {
			smallest := largest - protocol.PacketNumber(rand.IntN(30))
			if smallest < 0 {
				break
			}
			ranges = append(ranges, wire.AckRange{Smallest: smallest, Largest: largest})
			largest = smallest - protocol.PacketNumber(2+rand.IntN(30))
			if largest < 0 {
				break
			}
		}
		var want []protocol.PacketNumber
		for i := len(ranges) - 1; i >= 0; i-- {
			for p := ranges[i].Smallest; p <= ranges[i].Largest; p++ {
				if lost[p] {
					want = append(want, p)
				}
			}
		}
		var got []protocol.PacketNumber
		for p, sendTime := range lt.Acked(ranges) {
			require.Equal(t, start.Add(time.Duration(p)), sendTime)
			got = append(got, p)
		}
		require.Equal(t, want, got, "ranges: %v", ranges)
	}
}
