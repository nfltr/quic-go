//go:build quicacktrace

package ackhandler

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
)

// Trace mode (go test -tags quicacktrace, QUICACKTRACE=<dir>): each 1-RTT
// receiver (appDataReceivedPacketTracker) writes one JSON line per step of
// github.com/nfltr/link spec/AckFrequency.tla's receiver it takes, to a file
// of its own, after the step; link's spec/TraceAckFrequency.tla checks each
// file (link's make spec-traces). Times are microseconds since the tracker
// was made (one process, one monotonic clock).
//
//	Policy  T, R, MAD: the policy now applied (the default at creation, then ACK_FREQUENCY)
//	Recv    pn, el (ack-eliciting), ce (ECN-CE), t
//	Imm     an IMMEDIATE_ACK frame
//	Ignore  pn: IgnoreBelow
//	Ack     t, oq (only if queued: 0 a frame that rides another one), la (its largest)
//
// Every line also carries q (an ACK queued), alarm (the ACK alarm, -1:
// none) and lo (the lowest packet the history holds, -1: none).
const traceOn = true

type ackTrace struct {
	f     *os.File
	start monotime.Time
}

var ackTraceSeq atomic.Int64

func newAckTrace() *ackTrace {
	dir := os.Getenv("QUICACKTRACE")
	if dir == "" {
		return nil
	}
	f, err := os.Create(fmt.Sprintf("%s/ack-%d-%d.ndjson", dir, os.Getpid(), ackTraceSeq.Add(1)))
	if err != nil {
		panic(err)
	}
	return &ackTrace{f: f, start: monotime.Now()}
}

func (h *appDataReceivedPacketTracker) trace(ev string, kv ...any) {
	tr := h.tr
	if tr == nil {
		return
	}
	m := map[string]any{"ev": ev, "q": b2i(h.ackQueued), "alarm": int64(-1), "lo": int64(-1)}
	if !h.ackAlarm.IsZero() {
		m["alarm"] = tr.us(h.ackAlarm)
	}
	if len(h.packetHistory.ranges) > 0 {
		m["lo"] = int64(h.packetHistory.ranges[0].Start)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		switch v := kv[i+1].(type) {
		case monotime.Time:
			m[kv[i].(string)] = tr.us(v)
		case protocol.PacketNumber:
			m[kv[i].(string)] = int64(v)
		case bool:
			m[kv[i].(string)] = b2i(v)
		default:
			m[kv[i].(string)] = v
		}
	}
	line, _ := json.Marshal(m)
	_, _ = tr.f.Write(append(line, '\n'))
}

func (tr *ackTrace) us(t monotime.Time) int64 { return t.Sub(tr.start).Microseconds() }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
