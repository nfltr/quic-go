//go:build !quicacktrace

package ackhandler

import (
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/wire"
)

// lossTrace is the sender loss trace of -tags quicacktrace (loss_trace_on.go).
type lossTrace struct{}

func newLossTrace() *lossTrace { return nil }

func (h *sentPacketHandler) traceSent() {}

func (h *sentPacketHandler) traceLost(protocol.PacketNumber, *packet, string, monotime.Time, protocol.PacketNumber, time.Duration) {
}

func (h *sentPacketHandler) traceSpurious(protocol.PacketNumber, protocol.PacketNumber, time.Duration) {
}

func (h *sentPacketHandler) traceAck(*wire.AckFrame, monotime.Time) {}

// TraceDrop counts a dropped received packet under -tags quicacktrace.
func TraceDrop(string, protocol.PacketNumber) {}
