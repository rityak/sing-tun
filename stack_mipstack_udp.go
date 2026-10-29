package tun

import (
	"os"
	"sync"
	"sync/atomic"

	mips "github.com/metacubex/mipstack"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (s *Mipstack) forwardUDP(request *mips.UDPForwarderRequest) {
	flow := request.Flow()
	buffer := buf.NewSize(len(request.Payload()))
	_, _ = buffer.Write(request.Payload())
	s.handler.NewPacket(
		s.ctx,
		flow.Source,
		buffer,
		M.Metadata{
			Source:      M.SocksaddrFromNetIP(flow.Source),
			Destination: M.SocksaddrFromNetIP(flow.Destination),
		},
		// A packet delivered to an existing flow (mihomo's UDP fast path) never
		// asks for a writer, so the request is detached only here: that saves a
		// responder allocation and a forwarder lock per such packet. init must
		// run before NewPacket returns, while the request is pending; a request
		// nobody detached is dropped by the forwarder after this returns.
		func(N.PacketConn) N.PacketWriter {
			responder, err := request.Detach() // keeps the quote of an ICMP refusal
			if err != nil {
				return &mipsUDPWriter{err: err}
			}
			return &mipsUDPWriter{responder: responder}
		},
	)
}

// mipsUDPWriter answers the app; until the outcome of the session's dial it can
// also refuse the datagram with ICMP port unreachable (T-154, as sing-box's gvisor
// UDPBackWriter): HandshakeFailure refuses, HandshakeSuccess or the first reply
// drops the quote it keeps for that.
type mipsUDPWriter struct {
	responder *mips.UDPForwarderResponder
	err       error // the request could not be detached

	access  sync.Mutex
	decided atomic.Bool
}

func (w *mipsUDPWriter) HandshakeSuccess() error {
	if w.responder == nil || w.decided.Load() {
		return nil
	}
	w.access.Lock()
	defer w.access.Unlock()
	if !w.decided.Load() {
		_ = w.responder.RestrictToReplies() // no other responder call runs: replies wait for decided
		w.decided.Store(true)
	}
	return nil
}

func (w *mipsUDPWriter) HandshakeFailure(error) error {
	if w.responder == nil {
		return w.err
	}
	w.access.Lock()
	defer w.access.Unlock()
	if w.decided.Load() {
		return os.ErrInvalid
	}
	w.decided.Store(true)
	return w.responder.Reject()
}

func (w *mipsUDPWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if w.responder == nil {
		return w.err
	}
	if !w.decided.Load() {
		_ = w.HandshakeSuccess()
	}
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	}
	_, err := w.responder.ReplyFrom(buffer.Bytes(), destination.AddrPort())
	return err
}
