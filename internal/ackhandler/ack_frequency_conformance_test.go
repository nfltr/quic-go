package ackhandler

import (
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/nfltr/quic-go/internal/monotime"
	"github.com/nfltr/quic-go/internal/protocol"
	"github.com/nfltr/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

// TestAckFrequencyPolicyInvariants drives the 1-RTT tracker under an
// ACK_FREQUENCY policy through random reorderings (each packet at most
// reorder-1 places late) and losses, and checks spec/AckFrequency.tla's
// invariants (github.com/nfltr/link) after every packet: CountBound,
// AckWithinDelay, PromptLoss, and without loss NoReorderAck.
func TestAckFrequencyPolicyInvariants(t *testing.T) {
	const (
		n       = 5000
		thresh  = 9
		reorder = 10
		delay   = 5 * time.Millisecond
		step    = 20 * time.Microsecond
	)
	for _, tc := range []struct {
		name string
		loss float64
		late int // places
	}{
		{"reorder", 0, reorder - 1},
		{"reorder and loss", 0.01, reorder - 1},
		{"loss", 0.01, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewPCG(1, 2))
			// Each packet's place: its number plus up to late places.
			type pkt struct {
				pn  protocol.PacketNumber
				key float64
			}
			var order []pkt
			for pn := range protocol.PacketNumber(n) {
				if rng.Float64() < tc.loss {
					continue
				}
				order = append(order, pkt{pn, float64(pn) + rng.Float64()*float64(tc.late)})
			}
			sort.Slice(order, func(i, j int) bool { return order[i].key < order[j].key })

			tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
			tr.SetAckFrequency(ackFrequency(0, thresh, delay, reorder))
			rcvd := map[protocol.PacketNumber]bool{}
			largest, largestAcked := protocol.PacketNumber(-1), protocol.PacketNumber(-1)
			var unacked int
			var oldest monotime.Time
			var immediate int
			now := monotime.Now()
			ack := func(at monotime.Time) bool {
				f := tr.GetAckFrame(at, true)
				if f == nil {
					return false
				}
				largestAcked = f.LargestAcked()
				return true
			}
			for _, p := range order {
				now = now.Add(step)
				if ack(now) { // the run loop's ACK timer
					unacked = 0
				}
				require.NoError(t, tr.ReceivedPacket(p.pn, protocol.ECNNon, now, true))
				rcvd[p.pn] = true
				largest = max(largest, p.pn)
				if unacked == 0 {
					oldest = now
				}
				unacked++
				if ack(now) {
					if unacked <= thresh {
						immediate++
					}
					unacked = 0
				}
				// CountBound
				require.LessOrEqual(t, unacked, thresh)
				// AckWithinDelay: the alarm is at most delay after the oldest.
				if unacked > 0 {
					require.False(t, tr.GetAlarmTimeout().IsZero())
					require.LessOrEqual(t, tr.GetAlarmTimeout(), oldest.Add(delay))
				}
				// PromptLoss: a hole reorder deep is reported.
				for h := max(0, largest-3*reorder); h+reorder <= largest; h++ {
					if !rcvd[h] {
						require.GreaterOrEqual(t, largestAcked, h+reorder, "hole %d, largest %d", h, largest)
					}
				}
			}
			if tc.loss == 0 {
				// NoReorderAck
				require.Zero(t, immediate, "immediate ACKs for reordering within the threshold")
			} else {
				require.NotZero(t, immediate, "losses are reported at once")
			}
		})
	}
}
