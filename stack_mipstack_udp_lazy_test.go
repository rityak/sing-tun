package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// A handler that serves later packets of a flow through the writer of its
// first packet, as mihomo's UDP fast path does, never calls init again; the
// stack must keep delivering and replying (miray T-024).
func TestUDPPacketsWithoutInitKeepFlowReplies(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	var writer N.PacketWriter
	delivered := make(chan struct{}, 4096)
	h := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
		if writer == nil {
			writer = init(nil)
		}
		if bytes.Equal(b.Bytes(), []byte("echo")) {
			_ = writer.WritePacket(b, m.Destination)
		} else {
			b.Release()
		}
		delivered <- struct{}{}
	}}
	testStack(t, d, h, nil)

	d.in <- udpPacket(source, target, 443, []byte("first"))
	<-delivered
	const packets = 2000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < packets; i++ {
		d.in <- udpPacket(source, target, 443, []byte("later"))
		<-delivered
	}
	runtime.ReadMemStats(&after)
	t.Logf("%.1f allocations per packet without init", float64(after.Mallocs-before.Mallocs)/packets)

	d.in <- udpPacket(source, target, 443, []byte("echo"))
	<-delivered
	response := readPacket(t, d)
	if src, dst, proto, ok := mipsPacketAddresses(response); !ok || src != target || dst != source || proto != 17 {
		t.Fatalf("wrong UDP response %x", response)
	}
	if binary.BigEndian.Uint16(response[20:]) != 443 || !bytes.Equal(response[28:], []byte("echo")) {
		t.Fatalf("wrong UDP payload %x", response)
	}
}
