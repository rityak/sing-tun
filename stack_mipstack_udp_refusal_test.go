package tun

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var errTestRefused = errors.New("refused")

// A UDP session whose dial failed answers the app's datagram with ICMP port
// unreachable quoting it, as sing-box's gvisor stack does (T-154, RFC 1122
// §3.2.2.1); after success or a reply the writer refuses nothing.
func TestMipsUDPRefusal(t *testing.T) {
	for _, pair := range [][2]string{{"198.18.0.1", "8.8.8.8"}, {"fd00::1", "2001:4860:4860::8888"}} {
		source, target := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
		t.Run(pair[0], func(t *testing.T) {
			d := newMemoryTun()
			writers := make(chan N.PacketWriter, 4)
			testStack(t, d, &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, init func(N.PacketConn) N.PacketWriter) {
				b.Release()
				writers <- init(nil)
			}}, nil)

			request := udpPacket(source, target, 53, []byte("query"))
			d.in <- request
			w := <-writers
			if err := w.(N.HandshakeFailure).HandshakeFailure(errTestRefused); err != nil {
				t.Fatal(err)
			}
			icmp := readPacket(t, d)
			src, dst, proto, ok := mipsPacketAddresses(icmp)
			wantProto, wantType, wantCode, h := byte(1), byte(3), byte(3), 20
			if source.Is6() {
				wantProto, wantType, wantCode, h = 58, 1, 4, 40
			}
			if !ok || src != target || dst != source || proto != wantProto {
				t.Fatalf("not an ICMP to the app: %x", icmp)
			}
			if icmp[h] != wantType || icmp[h+1] != wantCode {
				t.Fatalf("ICMP type %d code %d, want %d/%d", icmp[h], icmp[h+1], wantType, wantCode)
			}
			if quote := icmp[h+8:]; len(quote) < h+8 || !bytes.HasPrefix(request, quote) {
				t.Fatalf("the ICMP does not quote the datagram: %x", quote)
			}

			d.in <- udpPacket(source, target, 53, []byte("again"))
			w = <-writers
			if err := N.ReportHandshakeSuccess(w); err != nil {
				t.Fatal(err)
			}
			if err := w.(N.HandshakeFailure).HandshakeFailure(errTestRefused); err == nil {
				t.Fatal("refused after success")
			}
			d.in <- udpPacket(source, target, 53, []byte("reply"))
			w = <-writers
			if err := w.WritePacket(buf.As([]byte("answer")), M.SocksaddrFrom(target, 53)); err != nil {
				t.Fatal(err)
			}
			_ = readPacket(t, d) // the reply
			if err := w.(N.HandshakeFailure).HandshakeFailure(errTestRefused); err == nil {
				t.Fatal("refused after a reply")
			}
			select {
			case p := <-d.out:
				t.Fatalf("unexpected packet %x", p)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}
