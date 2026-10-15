package tun

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// An empty UDP datagram is valid (keepalives use it) and reaches the
// handler, as with the mips and gVisor stacks (miray T-012).
func TestSystemForwardsEmptyUDP(t *testing.T) {
	delivered := make(chan int, 1)
	s := &System{logger: logger.NOP(), ctx: context.Background(), handler: &testHandler{
		udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
			delivered <- b.Len()
			b.Release()
		},
	}}
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     netip.MustParseAddr("198.18.0.1"),
		DstAddr:     netip.MustParseAddr("8.8.8.8"),
	})
	header.UDP(packet[header.IPv4MinimumSize:]).Encode(&header.UDPFields{SrcPort: 40000, DstPort: 53, Length: header.UDPMinimumSize})
	s.processPacket(packet)
	select {
	case n := <-delivered:
		if n != 0 {
			t.Fatalf("delivered %d bytes, want an empty datagram", n)
		}
	default:
		t.Fatal("empty UDP datagram was dropped")
	}
}
