//go:build !quicacktrace

package ackhandler

const traceOn = false

// ackTrace is the trace recorder of -tags quicacktrace (trace_on.go).
type ackTrace struct{}

func newAckTrace() *ackTrace { return nil }

func (h *appDataReceivedPacketTracker) trace(string, ...any) {}
