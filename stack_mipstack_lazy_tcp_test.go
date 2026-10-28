package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// acceptTCP is a handler that completes the handshake and closes.
func acceptTCP(_ context.Context, c net.Conn, _ M.Metadata) error {
	defer c.Close()
	return c.(N.HandshakeSuccess).HandshakeSuccess()
}

func tcpFlags(t *testing.T, packet []byte, ipv6 bool) byte {
	t.Helper()
	offset := 20
	if ipv6 {
		offset = 40
	}
	return packet[offset+13]
}

// The app's SYN is answered only once the handler knows the outcome of its dial
// (T-153): no SYN-ACK while it dials, a SYN-ACK after HandshakeSuccess.
func TestMipsLazyTCPWaitsForOutcome(t *testing.T) {
	d := newMemoryTun()
	decide := make(chan struct{})
	h := &testHandler{tcp: func(ctx context.Context, c net.Conn, m M.Metadata) error {
		<-decide
		return acceptTCP(ctx, c, m)
	}}
	testStack(t, d, h, nil)
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	d.in <- tcpPacket(source, target, 100, 0, 2, nil)
	select {
	case p := <-d.out:
		t.Fatalf("answered before the outcome: flags %#x", tcpFlags(t, p, false))
	case <-time.After(200 * time.Millisecond):
	}
	d.in <- tcpPacket(source, target, 100, 0, 2, nil) // the app retransmits its SYN meanwhile
	close(decide)
	if flags := tcpFlags(t, readPacket(t, d), false); flags&0x12 != 0x12 {
		t.Fatalf("want SYN-ACK after the outcome, got flags %#x", flags)
	}
}

// A failed dial, and a handler that returns without deciding, answer the SYN with
// a reset: the app sees a refused connection, not an accepted one closed at once.
func TestMipsLazyTCPRefusal(t *testing.T) {
	handlers := map[string]func(context.Context, net.Conn, M.Metadata) error{
		"failure": func(_ context.Context, c net.Conn, _ M.Metadata) error {
			return c.(N.HandshakeFailure).HandshakeFailure(errors.New("dial failed"))
		},
		"handler error": func(context.Context, net.Conn, M.Metadata) error { return errors.New("no route") },
		"close":         func(_ context.Context, c net.Conn, _ M.Metadata) error { return c.Close() },
		"linger 0": func(_ context.Context, c net.Conn, _ M.Metadata) error {
			return c.(interface{ SetLinger(int) error }).SetLinger(0)
		},
	}
	for name, handler := range handlers {
		for _, pair := range [][2]string{{"198.18.0.1", "8.8.8.8"}, {"fd00::1", "2001:4860:4860::8888"}} {
			t.Run(name+"/"+pair[0], func(t *testing.T) {
				d := newMemoryTun()
				testStack(t, d, &testHandler{tcp: handler}, nil)
				source, target := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
				d.in <- tcpPacket(source, target, 100, 0, 2, nil)
				p := readPacket(t, d)
				flags := tcpFlags(t, p, source.Is6())
				if flags&0x04 == 0 || flags&0x02 != 0 {
					t.Fatalf("want RST, got flags %#x", flags)
				}
				offset := 20
				if source.Is6() {
					offset = 40
				}
				if ack := binary.BigEndian.Uint32(p[offset+8:]); ack != 101 {
					t.Fatalf("RST acknowledges %d, want 101", ack)
				}
			})
		}
	}
}

// After a sniffer read completed the handshake, a failure resets the connection.
func TestMipsLazyTCPFailureAfterRead(t *testing.T) {
	d := newMemoryTun()
	h := &testHandler{tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
		if !c.(interface{ NeedHandshakeForRead() bool }).NeedHandshakeForRead() {
			return errors.New("pending connection reports no handshake needed")
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second)) // completes the handshake
		if c.(interface{ NeedHandshakeForRead() bool }).NeedHandshakeForRead() {
			return errors.New("handshake not completed by the first use")
		}
		buf := make([]byte, 5)
		if _, err := c.Read(buf); err != nil {
			return err
		}
		return c.(N.HandshakeFailure).HandshakeFailure(errors.New("dial failed"))
	}}
	testStack(t, d, h, nil)
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	d.in <- tcpPacket(source, target, 100, 0, 2, nil)
	synAck := readPacket(t, d)
	if tcpFlags(t, synAck, false)&0x12 != 0x12 {
		t.Fatalf("want SYN-ACK, got flags %#x", tcpFlags(t, synAck, false))
	}
	ack := binary.BigEndian.Uint32(synAck[24:]) + 1
	d.in <- tcpPacket(source, target, 101, ack, 16, nil)
	d.in <- tcpPacket(source, target, 101, ack, 24, []byte("hello"))
	for {
		if flags := tcpFlags(t, readPacket(t, d), false); flags&0x04 != 0 {
			return
		}
	}
}
