package tun

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	mips "github.com/metacubex/mipstack"
	M "github.com/metacubex/sing/common/metadata"
)

// mipsTCPMaxInFlight bounds the SYNs whose handler has not decided yet; with the
// lazy handshake one waits for the whole dial, so it matches the gvisor forwarder.
const mipsTCPMaxInFlight = 1024

func (s *Mipstack) forwardTCP(request *mips.TCPForwarderRequest) {
	flow := request.Flow()
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(flow.Source),
		Destination: M.SocksaddrFromNetIP(flow.Destination),
	}
	conn := &mipsLazyConn{
		ctx:        s.ctx,
		request:    request,
		localAddr:  net.TCPAddrFromAddrPort(flow.Destination),
		remoteAddr: net.TCPAddrFromAddrPort(flow.Source),
	}
	// The handler runs here, in the request's own goroutine, as mipstack requires
	// for Accept; a handler that returns without deciding resets the SYN.
	if err := s.handler.NewConnection(s.ctx, conn, metadata); err != nil {
		_ = conn.HandshakeFailure(err)
	}
	_ = conn.Close()
}

// mipsLazyConn answers the app's SYN only once the core knows how its dial went
// (T-153, as sing-box's lazy gvisor connection): HandshakeSuccess completes the
// handshake, HandshakeFailure and a close before it answer with a reset, so the
// app sees a refused connection (RFC 9293 §3.10.7.1) instead of an accepted one
// that closes at once. A read or write before the outcome completes the handshake
// first (a sniffer). The undecided request must be completed in the handler's
// goroutine; NeedHandshakeForRead tells the core not to read it from another.
type mipsLazyConn struct {
	ctx        context.Context
	request    *mips.TCPForwarderRequest
	localAddr  net.Addr
	remoteAddr net.Addr

	access sync.Mutex
	done   bool
	err    error
	conn   *mips.TCPConn
}

func (c *mipsLazyConn) handshake() error {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.done {
		c.done = true
		c.conn, c.err = c.request.Accept(c.ctx)
	}
	return c.err
}

// reject resets an undecided request and reports whether it was undecided;
// otherwise it returns the accepted connection, nil if the handshake failed.
func (c *mipsLazyConn) reject(err error) (bool, *mips.TCPConn) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.done {
		return false, c.conn
	}
	c.done, c.err = true, err
	_ = c.request.Reject()
	return true, nil
}

func (c *mipsLazyConn) HandshakeSuccess() error { return c.handshake() }

// HandshakeFailure resets the connection: the SYN if it is still undecided, the
// accepted connection otherwise (a sniffer read first).
func (c *mipsLazyConn) HandshakeFailure(err error) error {
	if rejected, conn := c.reject(err); !rejected && conn != nil {
		_ = conn.SetLinger(0)
	}
	return nil
}

func (c *mipsLazyConn) NeedHandshakeForRead() bool  { return c.pending() }
func (c *mipsLazyConn) NeedHandshakeForWrite() bool { return c.pending() }

func (c *mipsLazyConn) pending() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.done
}

func (c *mipsLazyConn) established() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.done && c.err == nil
}

func (c *mipsLazyConn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.Read(b)
}

func (c *mipsLazyConn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}

func (c *mipsLazyConn) WriteTo(w io.Writer) (int64, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.WriteTo(w)
}

func (c *mipsLazyConn) ReadFrom(r io.Reader) (int64, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.conn.ReadFrom(r)
}

func (c *mipsLazyConn) Close() error {
	if _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *mipsLazyConn) CloseRead() error {
	if _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.CloseRead()
	}
	return nil
}

func (c *mipsLazyConn) CloseWrite() error {
	if _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.CloseWrite()
	}
	return nil
}

// SetLinger(0) before the outcome is a refusal, after it a reset.
func (c *mipsLazyConn) SetLinger(sec int) error {
	if sec != 0 {
		if err := c.handshake(); err != nil {
			return err
		}
		return c.conn.SetLinger(sec)
	}
	if _, conn := c.reject(net.ErrClosed); conn != nil {
		return conn.SetLinger(0)
	}
	return nil
}

func (c *mipsLazyConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *mipsLazyConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *mipsLazyConn) SetDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetDeadline(t)
}

func (c *mipsLazyConn) SetReadDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetReadDeadline(t)
}

func (c *mipsLazyConn) SetWriteDeadline(t time.Time) error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

// After the handshake the relay works on the mipstack connection itself.
func (c *mipsLazyConn) ReaderReplaceable() bool { return c.established() }
func (c *mipsLazyConn) WriterReplaceable() bool { return c.established() }
func (c *mipsLazyConn) Upstream() any {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn == nil {
		return nil // not a typed nil: unwrapping stops here before the handshake
	}
	return c.conn
}
