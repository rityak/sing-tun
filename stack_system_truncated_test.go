package tun

import (
	"net/netip"
	"testing"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/logger"
)

// A packet whose transport header is cut short must be dropped, not indexed:
// any local process can write such a packet to the TUN (miray T-012).
func TestSystemDropsTruncatedTransportHeader(t *testing.T) {
	s := &System{logger: logger.NOP()}
	for _, protocol := range []tcpip.TransportProtocolNumber{header.TCPProtocolNumber, header.UDPProtocolNumber, header.ICMPv4ProtocolNumber} {
		for _, size := range []int{0, 3, 7} {
			packet := make([]byte, header.IPv4MinimumSize+size)
			header.IPv4(packet).Encode(&header.IPv4Fields{
				TotalLength: uint16(len(packet)),
				TTL:         64,
				Protocol:    uint8(protocol),
				SrcAddr:     netip.MustParseAddr("198.18.0.1"),
				DstAddr:     netip.MustParseAddr("8.8.8.8"),
			})
			if s.processPacket(packet) {
				t.Fatalf("IPv4 protocol %d with %d-byte transport header written back", protocol, size)
			}
		}
	}
	for _, protocol := range []tcpip.TransportProtocolNumber{header.TCPProtocolNumber, header.UDPProtocolNumber, header.ICMPv6ProtocolNumber} {
		packet := make([]byte, header.IPv6MinimumSize+5)
		header.IPv6(packet).Encode(&header.IPv6Fields{
			PayloadLength:     5,
			TransportProtocol: protocol,
			HopLimit:          64,
			SrcAddr:           netip.MustParseAddr("fdfe:dcba:9876::1"),
			DstAddr:           netip.MustParseAddr("2001:4860:4860::8888"),
		})
		if s.processPacket(packet) {
			t.Fatalf("IPv6 protocol %d with a 5-byte transport header written back", protocol)
		}
	}
	// A TCP data offset beyond the payload is truncated too.
	tcp := make([]byte, header.TCPMinimumSize)
	header.TCP(tcp).Encode(&header.TCPFields{DataOffset: 60})
	if transportHeaderValid(header.TCPProtocolNumber, tcp) {
		t.Fatal("TCP data offset beyond the payload accepted")
	}
}
