//go:build quicacktrace

package ackhandler

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/wire"
)

// Sender loss trace (-tags quicacktrace, QUICLOSSTRACE=<dir>): each
// sentPacketHandler writes loss-<pid>-<seq>.ndjson, one JSON line per
// 1-RTT ack-eliciting packet declared lost and per declared-lost packet
// later acknowledged (spurious). Times are microseconds.
//
//	Lost  pn, why (time: time threshold, pkt: packet threshold, pto: a PTO
//	      probe's retransmission), len, age (since sent), dist (packets
//	      acked above it), srtt, latest, var, ld (loss delay), thr (packet
//	      threshold, 0: off), te (time threshold, eighths over 1 RTT)
//	Spur  pn, why, late (acknowledged after lostPackets forgot it: counted
//	      as why-late), reord (packets), treord (send to ack, ack delay off)
//	Sum   every 65536 packets sent: sent and the counts by cause so far
type lossTrace struct {
	f    *os.File
	why  map[protocol.PacketNumber]string // declared lost, not yet acknowledged
	all  lostPacketTracker                // every one declared lost, unbounded: lostPackets forgets after 3 PTOs
	sent uint64
	lost map[string]uint64
	spur map[string]uint64
}

func newLossTrace() *lossTrace {
	dir := os.Getenv("QUICLOSSTRACE")
	if dir == "" {
		return nil
	}
	f, err := os.Create(fmt.Sprintf("%s/loss-%d-%d.ndjson", dir, os.Getpid(), ackTraceSeq.Add(1)))
	if err != nil {
		panic(err)
	}
	return &lossTrace{f: f, why: map[protocol.PacketNumber]string{}, lost: map[string]uint64{}, spur: map[string]uint64{}}
}

func (tr *lossTrace) line(m map[string]any) {
	b, _ := json.Marshal(m)
	_, _ = tr.f.Write(append(b, '\n'))
}

func (h *sentPacketHandler) traceSent() {
	tr := h.ltr
	if tr == nil {
		return
	}
	if tr.sent++; tr.sent%65536 == 0 {
		tr.line(map[string]any{"ev": "Sum", "sent": tr.sent, "lost": tr.lost, "spur": tr.spur})
	}
}

func (h *sentPacketHandler) traceLost(pn protocol.PacketNumber, p *packet, why string, now monotime.Time, dist protocol.PacketNumber, lossDelay time.Duration) {
	tr := h.ltr
	if tr == nil || p.EncryptionLevel != protocol.Encryption1RTT {
		return
	}
	tr.lost[why]++
	tr.why[pn] = why
	if l := tr.all.lostPackets; len(l) == 0 || l[len(l)-1].PacketNumber < pn {
		tr.all.lostPackets = append(l, lostPacket{pn, p.SendTime})
	} else if i, found := tr.all.search(pn); !found {
		tr.all.lostPackets = slices.Insert(l, i, lostPacket{pn, p.SendTime})
	}
	thr := int64(h.appDataPacketThreshold)
	if h.packetThresholdDisabled {
		thr = 0
	}
	tr.line(map[string]any{
		"ev": "Lost", "pn": int64(pn), "why": why, "len": int64(p.Length),
		"age": now.Sub(p.SendTime).Microseconds(), "dist": int64(dist),
		"srtt": h.rttStats.SmoothedRTT().Microseconds(), "latest": h.rttStats.LatestRTT().Microseconds(),
		"var": h.rttStats.MeanDeviation().Microseconds(), "ld": lossDelay.Microseconds(),
		"thr": thr, "te": h.timeThresholdEighths,
	})
}

func (h *sentPacketHandler) traceSpurious(pn protocol.PacketNumber, reord protocol.PacketNumber, treord time.Duration) {
	h.traceSpur(pn, reord, treord, false)
}

func (h *sentPacketHandler) traceSpur(pn protocol.PacketNumber, reord protocol.PacketNumber, treord time.Duration, late bool) {
	tr := h.ltr
	if tr == nil {
		return
	}
	why, ok := tr.why[pn]
	if !ok {
		return
	}
	delete(tr.why, pn)
	k := why
	if late {
		k += "-late"
	}
	tr.spur[k]++
	tr.line(map[string]any{"ev": "Spur", "pn": int64(pn), "why": why, "late": late, "reord": int64(reord), "treord": treord.Microseconds()})
}

// traceAck finds the declared-lost packets an ACK acknowledges that
// detectSpuriousLosses (before it) did not: PTO probes' packets, and late
// ones lostPackets no longer held (late: 3 PTOs, or past its bound).
func (h *sentPacketHandler) traceAck(ack *wire.AckFrame, ackTime monotime.Time) {
	tr := h.ltr
	if tr == nil {
		return
	}
	var acked []protocol.PacketNumber
	for pn, sendTime := range tr.all.Acked(ack.AckRanges) {
		acked = append(acked, pn)
		h.traceSpur(pn, h.hist.Difference(ack.LargestAcked(), pn), ackTime.Sub(sendTime), tr.why[pn] != "pto")
	}
	tr.all.DeleteAll(acked)
}

var (
	traceStart = time.Now() // t in drops-*.ndjson: seconds since, as GODEBUG=gctrace=1's @
	drops      sync.Map     // reason -> *atomic.Uint64
	dropsFile  = sync.OnceValue(func() *os.File {
		dir := os.Getenv("QUICLOSSTRACE")
		if dir == "" {
			return nil
		}
		f, _ := os.Create(fmt.Sprintf("%s/drops-%d.ndjson", dir, os.Getpid()))
		return f
	})
)

// TraceDrop counts a received packet the receiver drops or forgets
// unacknowledged, per process in <dir>/drops-<pid>.ndjson: queue (a full
// receive queue), dup (1-RTT, below what the history still holds or
// already in it), evict (a range the history dropped past MaxNumAckRanges;
// pn: its highest packet). A line per dup and evict, and at 1, 2, 4, ...
// and every 1024 of a reason; t: seconds since the process started.
func TraceDrop(why string, pn protocol.PacketNumber) {
	f := dropsFile()
	if f == nil {
		return
	}
	c, _ := drops.LoadOrStore(why, new(atomic.Uint64))
	n := c.(*atomic.Uint64).Add(1)
	if why != "queue" || n&(n-1) == 0 || n%1024 == 0 {
		fmt.Fprintf(f, "{\"ev\":\"Drop\",\"why\":%q,\"n\":%d,\"pn\":%d,\"t\":%.3f}\n", why, n, pn, time.Since(traceStart).Seconds())
	}
}
