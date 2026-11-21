package congestion

import (
	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart(priorInFlight protocol.ByteCount)
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	OnSpuriousLoss(number protocol.PacketNumber)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}

// AckedPacketInfo is one packet an ACK newly acknowledged.
type AckedPacketInfo struct {
	PacketNumber protocol.PacketNumber
	BytesAcked   protocol.ByteCount
	ReceivedTime monotime.Time
}

// LostPacketInfo is one packet declared lost.
type LostPacketInfo struct {
	PacketNumber protocol.PacketNumber
	BytesLost    protocol.ByteCount
}

// A SendAlgorithmEx also takes each ACK or loss event as a whole: the packets
// it acknowledged and those it declared lost (BBR's bandwidth sampler needs both),
// and the lowest packet number still outstanding (state below it is obsolete).
type SendAlgorithmEx interface {
	SendAlgorithmWithDebugInfos
	OnCongestionEventEx(priorInFlight protocol.ByteCount, eventTime monotime.Time, acked []AckedPacketInfo, lost []LostPacketInfo, leastUnacked protocol.PacketNumber)
}
