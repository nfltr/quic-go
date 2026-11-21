package bbr

import (
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
)

// minPacingDelay matches the cubic pacer's.
const minPacingDelay = time.Millisecond

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent protocol.ByteCount
	maxDatagramSize  protocol.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() protocol.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() protocol.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * protocol.InitialPacketSize,
		maxDatagramSize:  protocol.InitialPacketSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now monotime.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (p.getBandwidth()*protocol.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 { // protect against overflows
		budget = protocol.ByteCount(1<<62 - 1)
	}
	return min(p.maxBurstSize(), budget)
}

func (p *Pacer) maxBurstSize() protocol.ByteCount {
	return max(
		protocol.ByteCount((maxBurstPacingDelayMultiplier*minPacingDelay).Nanoseconds())*p.getBandwidth()/1e9,
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(p.getBandwidth())
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(minPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *Pacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}
