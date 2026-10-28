//go:build with_gvisor

package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing/common"
	M "github.com/metacubex/sing/common/metadata"
)

type TCPForwarder struct {
	ctx                  context.Context
	stack                *stack.Stack
	handler              Handler
	inet4LoopbackAddress []tcpip.Address
	inet6LoopbackAddress []tcpip.Address
	tun                  GVisorTun
	forwarder            *tcp.Forwarder
}

func NewTCPForwarder(ctx context.Context, stack *stack.Stack, handler Handler) *TCPForwarder {
	return NewTCPForwarderWithLoopback(ctx, stack, handler, nil, nil, nil)
}

func NewTCPForwarderWithLoopback(ctx context.Context, stack *stack.Stack, handler Handler, inet4LoopbackAddress []netip.Addr, inet6LoopbackAddress []netip.Addr, tun GVisorTun) *TCPForwarder {
	forwarder := &TCPForwarder{
		ctx:                  ctx,
		stack:                stack,
		handler:              handler,
		inet4LoopbackAddress: common.Map(inet4LoopbackAddress, AddressFromAddr),
		inet6LoopbackAddress: common.Map(inet6LoopbackAddress, AddressFromAddr),
		tun:                  tun,
	}
	forwarder.forwarder = tcp.NewForwarder(stack, 0, 1024, forwarder.Forward)
	return forwarder
}

func (f *TCPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	for _, inet4LoopbackAddress := range f.inet4LoopbackAddress {
		if id.LocalAddress == inet4LoopbackAddress {
			ipHdr := pkt.Network().(header.IPv4)
			ipHdr.SetDestinationAddressWithChecksumUpdate(ipHdr.SourceAddress())
			ipHdr.SetSourceAddressWithChecksumUpdate(inet4LoopbackAddress)
			tcpHdr := header.TCP(pkt.TransportHeader().Slice())
			tcpHdr.SetChecksum(0)
			tcpHdr.SetChecksum(^checksum.Combine(pkt.Data().Checksum(), tcpHdr.CalculateChecksum(
				header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
			)))
			f.tun.WritePacket(pkt)
			return true
		}
	}
	for _, inet6LoopbackAddress := range f.inet6LoopbackAddress {
		if id.LocalAddress == inet6LoopbackAddress {
			ipHdr := pkt.Network().(header.IPv6)
			ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
			ipHdr.SetSourceAddress(inet6LoopbackAddress)
			tcpHdr := header.TCP(pkt.TransportHeader().Slice())
			tcpHdr.SetChecksum(0)
			tcpHdr.SetChecksum(^checksum.Combine(pkt.Data().Checksum(), tcpHdr.CalculateChecksum(
				header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
			)))
			f.tun.WritePacket(pkt)
			return true
		}
	}
	return f.forwarder.HandlePacket(id, pkt)
}

// Forward hands the SYN to the handler undecided (T-153, as sing-box's lazy
// gvisor connection): the handshake completes on HandshakeSuccess or on the
// first use, and a failure or a close before it resets the SYN, so the app sees
// a refused connection (RFC 9293 §3.10.7.1) instead of one that closes at once.
// The forwarder runs Forward in a goroutine of its own and bounds undecided SYNs.
func (f *TCPForwarder) Forward(r *tcp.ForwarderRequest) {
	id := r.ID()
	conn := &gLazyConn{
		ctx:        f.ctx,
		request:    r,
		localAddr:  M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort).TCPAddr(),
		remoteAddr: M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort).TCPAddr(),
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort),
		Destination: M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort),
	}
	if err := f.handler.NewConnection(f.ctx, conn, metadata); err != nil {
		_ = conn.HandshakeFailure(err)
	}
	_ = conn.Close()
}

type gLazyConn struct {
	ctx        context.Context
	request    *tcp.ForwarderRequest
	localAddr  net.Addr
	remoteAddr net.Addr

	access   sync.Mutex
	done     bool
	err      error
	endpoint tcpip.Endpoint
	conn     *gonet.TCPConn
}

func (c *gLazyConn) handshake() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.done {
		return c.err
	}
	c.done = true
	var wq waiter.Queue
	var cancel context.CancelFunc
	if parentDone := c.ctx.Done(); parentDone != nil {
		var handshakeCtx context.Context
		handshakeCtx, cancel = context.WithCancel(context.Background())
		go func() {
			select {
			case <-parentDone:
				wq.Notify(wq.Events())
			case <-handshakeCtx.Done():
			}
		}()
	}
	endpoint, err := c.request.CreateEndpoint(&wq)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		c.request.Complete(true)
		c.err = gonet.TranslateNetstackError(err)
		return c.err
	}
	c.request.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveInterval)
	c.endpoint, c.conn = endpoint, gonet.NewTCPConn(&wq, endpoint)
	return nil
}

// reject resets an undecided SYN and reports whether it was undecided; otherwise
// it returns the accepted endpoint and connection, nil if the handshake failed.
func (c *gLazyConn) reject(err error) (bool, tcpip.Endpoint, *gonet.TCPConn) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.done {
		return false, c.endpoint, c.conn
	}
	c.done, c.err = true, err
	c.request.Complete(true)
	return true, nil, nil
}

func (c *gLazyConn) HandshakeSuccess() error { return c.handshake() }

// HandshakeFailure resets the SYN if it is undecided, the connection otherwise.
func (c *gLazyConn) HandshakeFailure(err error) error {
	if rejected, endpoint, _ := c.reject(err); !rejected && endpoint != nil {
		endpoint.Abort()
	}
	return nil
}

func (c *gLazyConn) NeedHandshakeForRead() bool  { return c.pending() }
func (c *gLazyConn) NeedHandshakeForWrite() bool { return c.pending() }

func (c *gLazyConn) pending() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.done
}

func (c *gLazyConn) established() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.done && c.err == nil
}

func (c *gLazyConn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.Read(b)
}

func (c *gLazyConn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}

func (c *gLazyConn) Close() error {
	if _, _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *gLazyConn) CloseRead() error {
	if _, _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.CloseRead()
	}
	return nil
}

func (c *gLazyConn) CloseWrite() error {
	if _, _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.CloseWrite()
	}
	return nil
}

// SetLinger(0) before the outcome is a refusal, after it a reset.
func (c *gLazyConn) SetLinger(sec int) error {
	if sec != 0 {
		return nil
	}
	if rejected, endpoint, _ := c.reject(net.ErrClosed); !rejected && endpoint != nil {
		endpoint.Abort()
	}
	return nil
}

func (c *gLazyConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *gLazyConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *gLazyConn) SetDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetDeadline(t)
}

func (c *gLazyConn) SetReadDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetReadDeadline(t)
}

func (c *gLazyConn) SetWriteDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

// After the handshake the relay works on the gonet connection itself.
func (c *gLazyConn) ReaderReplaceable() bool { return c.established() }
func (c *gLazyConn) WriterReplaceable() bool { return c.established() }
func (c *gLazyConn) Upstream() any {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn == nil {
		return nil // not a typed nil: unwrapping stops here before the handshake
	}
	return c.conn
}
