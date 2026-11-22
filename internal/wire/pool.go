package wire

import (
	"sync"

	"github.com/nfltr/quic-go/internal/protocol"
)

var pool, jumboPool sync.Pool

func init() {
	pool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxPacketBufferSize),
			fromPool: true,
		}
	}
	jumboPool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxJumboPacketSize),
			fromPool: true,
		}
	}
}

func GetStreamFrame() *StreamFrame {
	f := pool.Get().(*StreamFrame)
	return f
}

// GetStreamFrameFor is a STREAM frame for up to n bytes of data:
// GetStreamFrame's up to MaxPacketBufferSize, else one of
// MaxJumboPacketSize (Config.MaxPacketSize above 1452).
func GetStreamFrameFor(n protocol.ByteCount) *StreamFrame {
	if n <= protocol.MaxPacketBufferSize {
		return GetStreamFrame()
	}
	return jumboPool.Get().(*StreamFrame)
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	switch protocol.ByteCount(cap(f.Data)) {
	case protocol.MaxPacketBufferSize:
		pool.Put(f)
	case protocol.MaxJumboPacketSize:
		jumboPool.Put(f)
	default:
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
}
