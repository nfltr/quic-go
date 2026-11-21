// Package bbr is BBR (v1) congestion control: a port of Chromium QUICHE's
// BbrSender and BandwidthSampler (quic/core/congestion_control), taken from
// Hysteria (github.com/apernet/hysteria, core/internal/congestion/bbr at
// 7040c167, MIT, see LICENSE) with these changes for this fork:
//
//   - types are the fork's internal protocol types; the RTT stats are the
//     connection's *utils.RTTStats; golang.org/x/exp/constraints is spelled out;
//   - OnCongestionEventEx gets the sender's lowest outstanding packet number
//     to drop obsolete sampler state (Hysteria estimated it as the largest
//     acked - 2, which drops the samples of packets a reordering path acks late);
//   - only ack-eliciting packets are paced (as the cubic sender);
//   - New picks the conservative profile (overshoot detection, drain to
//     target, overestimate avoidance): no queue drops on a deep tail-drop
//     bottleneck where the standard profile lost 1-2 %.
//
// Select it with quic.Config.CongestionControl = quic.CongestionControlBBR.
package bbr
