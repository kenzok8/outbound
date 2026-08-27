package http

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/http2"
)

var httpRequestLinePattern = regexp.MustCompile(`^\S+ \S+ HTTP/[\d.]+$`)

var httpMethods = [][]byte{
	[]byte("GET"),
	[]byte("HEAD"),
	[]byte("POST"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("CONNECT"),
	[]byte("OPTIONS"),
	[]byte("TRACE"),
	[]byte("PATCH"),
	[]byte("PRI"),
}

type Conn struct {
	nextDialer netproxy.Dialer
	conn       netproxy.Conn

	proxy        *HttpProxy
	magicNetwork string
	tgt          string
	// handshakeDeadline preserves the original dial budget for the lazy
	// proxy handshake that starts on the first Read/Write.
	handshakeDeadline time.Time

	ctxShakeFinished    context.Context
	cancelShakeFinished func()
	muShake             sync.Mutex
	muFinishShakeFuncs  sync.Mutex
	finishShakeFuncs    []func(conn netproxy.Conn)

	isH2      bool
	closeOnce sync.Once

	pendingFirstWrite bytes.Buffer
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetDeadline(t)
		})
		return nil
	}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetReadDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetReadDeadline(t)
		})
		return nil
	}
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetWriteDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetWriteDeadline(t)
		})
		return nil
	}
}

func NewConn(ctx context.Context, nextDialer netproxy.Dialer, proxy *HttpProxy, addr string, network string) *Conn {
	ctxShakeFinished, cancelShakeFinished := context.WithCancel(context.Background())
	return &Conn{
		nextDialer:          nextDialer,
		proxy:               proxy,
		tgt:                 addr,
		magicNetwork:        network,
		handshakeDeadline:   netproxy.CaptureDeadline(ctx),
		ctxShakeFinished:    ctxShakeFinished,
		cancelShakeFinished: cancelShakeFinished,
	}
}

func (c *Conn) newHandshakeContext() (context.Context, context.CancelFunc) {
	return netproxy.NewDialTimeoutContextWithCapturedDeadline(c.handshakeDeadline)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.muShake.Lock()
	defer c.muShake.Unlock()
	defer func() {
		if err == nil && c.conn != nil {
			c.muFinishShakeFuncs.Lock()
			defer c.muFinishShakeFuncs.Unlock()
			// SetDeadline after c.conn filled.
			for _, f := range c.finishShakeFuncs {
				f(c.conn)
			}
		}
	}()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return 0, io.EOF
		}
		return c.conn.Write(b)
	default:
		// Handshake
		handshakeInput := b
		hadPendingFirstWrite := c.pendingFirstWrite.Len() > 0
		if hadPendingFirstWrite {
			_, _ = c.pendingFirstWrite.Write(b)
			handshakeInput = c.pendingFirstWrite.Bytes()
		}

		firstLine, hasFirstLine := readHTTPFirstLine(handshakeInput)
		if !c.proxy.https && !hasFirstLine && isPossibleHTTPRequestLinePrefix(handshakeInput) {
			if !hadPendingFirstWrite {
				_, _ = c.pendingFirstWrite.Write(handshakeInput)
			}
			return len(b), nil
		}
		isHttpReq := !c.proxy.https && httpRequestLinePattern.Match(firstLine)
		payload := b
		bufferedPrefixLen := 0
		if hadPendingFirstWrite && !isHttpReq {
			payload = bytes.Clone(handshakeInput)
			bufferedPrefixLen = len(payload) - len(b)
		}

		var req *http.Request
		if isHttpReq && !c.proxy.https {
			// HTTP Request

			req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(handshakeInput)))
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					// Request more data.
					if c.pendingFirstWrite.Len() == 0 {
						_, _ = c.pendingFirstWrite.Write(handshakeInput)
					}
					return len(b), nil
				}
				// Error
				return 0, err
			}

			req.URL.Scheme = "http"
			req.URL.Host = c.tgt
			c.pendingFirstWrite.Reset()
		} else {
			// Arbitrary TCP

			// HACK. http.ReadRequest also does this.
			reqURL, err := url.Parse("http://" + c.tgt)
			if err != nil {
				return 0, err
			}
			method := "CONNECT"
			if !c.proxy.transport {
				reqURL.Scheme = ""
			} else {
				method = "PUT"
			}

			req, err = http.NewRequest(method, reqURL.String(), nil)
			if err != nil {
				return 0, err
			}
			c.pendingFirstWrite.Reset()
		}
		defer c.cancelShakeFinished()
		if c.proxy.Host != "" {
			req.Host = c.proxy.Host
		} else if c.proxy.transport {
			req.Host = "www.example.com"
		}
		if c.proxy.transport {
			req.URL.Path = c.proxy.Path
		}
		req.Close = false
		if c.proxy.HaveAuth {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.proxy.Username+":"+c.proxy.Password)))
		}
		// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.1.2
		// As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.
		if len(req.Header.Values("Proxy-Connection")) > 0 {
			req.Header.Del("Proxy-Connection")
		}

		connectHttp1 := func(handshakeCtx context.Context, rawConn netproxy.Conn) (conn netproxy.Conn, n int, err error) {
			restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(handshakeCtx, rawConn)
			if err != nil {
				return nil, 0, err
			}
			defer restoreDeadline()

			proxyReq := req.Clone(context.Background())
			err = proxyReq.WriteProxy(rawConn)
			if err != nil {
				return nil, 0, err
			}

			if isHttpReq {
				// Forward-proxy request: the proxy streams the origin's
				// response verbatim, so the caller keeps reading rawConn.
				// Allow read here to void race.
				return rawConn, len(b), nil
			}

			// We should read tcp connection here, and we will be guaranteed higher priority by chShakeFinished.
			// The response is consumed through a bufio.Reader so any bytes the
			// reader pulled past the header (coalesced early tunnel data) are
			// preserved via prefixedConn instead of being lost to the kernel
			// buffer.
			br := bufio.NewReaderSize(rawConn, 4096)
			resp, err := http.ReadResponse(br, proxyReq)
			if err != nil {
				if resp != nil {
					_ = resp.Body.Close()
				}
				return nil, 0, err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
				return nil, 0, err
			}
			conn = rawConn
			if buffered := br.Buffered(); buffered > 0 {
				prefix := make([]byte, buffered)
				read, _ := io.ReadFull(br, prefix)
				if read > 0 {
					conn = &prefixedConn{Conn: rawConn, prefix: prefix[:read]}
				}
			}
			written, err := conn.Write(payload)
			if err != nil {
				if written <= bufferedPrefixLen {
					return conn, 0, err
				}
				return conn, written - bufferedPrefixLen, err
			}
			if written < len(payload) {
				if written <= bufferedPrefixLen {
					return conn, 0, io.ErrShortWrite
				}
				return conn, written - bufferedPrefixLen, io.ErrShortWrite
			}
			return conn, len(b), nil
		}

		// Thanks to v2fly/v2ray-core.
		connectHttp2 := func(handshakeCtx context.Context, rawConn netproxy.Conn, h2clientConn *http2.ClientConn, req *http.Request) (conn *http2Conn, n int, err error) {
			proxyReq := req.Clone(context.Background())
			pr, pw := io.Pipe()
			proxyReq.Body = pr

			reqCtx := context.Background()
			cancelReqCtx := func() {}
			if deadline, ok := handshakeCtx.Deadline(); ok {
				if time.Until(deadline) <= 0 {
					_ = pw.CloseWithError(context.DeadlineExceeded)
					return nil, 0, context.DeadlineExceeded
				}
				reqCtx, cancelReqCtx = context.WithDeadline(context.Background(), deadline)
				proxyReq = proxyReq.WithContext(reqCtx)
			}
			defer cancelReqCtx()

			var pErr error
			done := make(chan struct{})

			go func() {
				defer close(done)
				_, pErr = pw.Write(b)
			}()

			resp, err := h2clientConn.RoundTrip(proxyReq) // nolint: bodyclose
			if err != nil {
				_ = pw.CloseWithError(err)
				<-done
				if reqErr := reqCtx.Err(); reqErr != nil {
					if errors.Is(reqErr, context.DeadlineExceeded) {
						return nil, 0, context.DeadlineExceeded
					}
					return nil, 0, reqErr
				}
				return nil, 0, err
			}

			<-done
			if pErr != nil {
				_ = resp.Body.Close()
				return nil, 0, pErr
			}

			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				return nil, 0, fmt.Errorf("proxy responded with non 200 code: %v", resp.Status)
			}
			return newHTTP2Conn(&netproxy.FakeNetConn{
				Conn: rawConn,
			}, pw, resp.Body), len(b), nil
		}

		if !c.proxy.https {
			ctx, cancel := c.newHandshakeContext()
			defer cancel()
			conn, err := c.nextDialer.DialContext(ctx, c.magicNetwork, c.proxy.Addr)
			if err != nil {
				return 0, err
			}
			c.conn = conn
			effConn, n, err := connectHttp1(ctx, conn)
			if err == nil {
				c.conn = effConn
			}
			return n, err
		}

		handshakeCtx, cancel := c.newHandshakeContext()
		defer cancel()
		rawConn, h2Conn, err := connPool.GetConn(handshakeCtx, c.nextDialer, c.proxy.Addr, c.magicNetwork)
		if err != nil {
			return 0, err
		}
		if h2Conn != nil {
			proxyConn, n, err := connectHttp2(handshakeCtx, rawConn, h2Conn, req)
			if err != nil {
				return 0, err
			}
			c.conn = proxyConn
			c.isH2 = true
			return n, nil
		} else {
			c.conn = rawConn
			effConn, n, err := connectHttp1(handshakeCtx, rawConn)
			if err == nil {
				c.conn = effConn
			}
			return n, err
		}
	}
}

func readHTTPFirstLine(b []byte) ([]byte, bool) {
	lineEnd := bytes.IndexByte(b, '\n')
	if lineEnd < 0 {
		return nil, false
	}
	return bytes.TrimRight(b[:lineEnd], "\r"), true
}

func isPossibleHTTPRequestLinePrefix(b []byte) bool {
	method := b
	if methodEnd := bytes.IndexByte(b, ' '); methodEnd >= 0 {
		method = b[:methodEnd]
	}
	if len(method) == 0 {
		return false
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	for _, httpMethod := range httpMethods {
		if bytes.Equal(method, httpMethod) {
			return true
		}
		if bytes.HasPrefix(httpMethod, method) {
			return true
		}
	}
	return false
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.ctxShakeFinished.Done()
	if c.conn == nil {
		return 0, io.EOF
	}
	return c.conn.Read(b)
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// HTTP/2 connections are managed by the connection pool, don't close them.
		// HTTP/1.1 connections should be closed to prevent resource leaks.
		if !c.isH2 && c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) *http2Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

// prefixedConn replays bytes a handshake bufio.Reader consumed past the
// CONNECT response before handing reads to the underlying tunnel, so
// coalesced early application data is not dropped.
type prefixedConn struct {
	netproxy.Conn
	prefix []byte
}

func (p *prefixedConn) Read(b []byte) (n int, err error) {
	if len(p.prefix) > 0 {
		n = copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	inErr := h.in.Close()
	outErr := h.out.Close()
	if inErr != nil && outErr != nil {
		return fmt.Errorf("in.Close(): %w; out.Close(): %v", inErr, outErr)
	}
	if inErr != nil {
		return inErr
	}
	return outErr
}

type h2Conn struct {
	rawConn netproxy.Conn
	h2Conn  *http2.ClientConn
}

type lockedList struct {
	l    *list.List
	mu   sync.Mutex
	refs int
}

func newLockedList() *lockedList {
	return &lockedList{
		l:    list.New(),
		mu:   sync.Mutex{},
		refs: 0,
	}
}

type poolIdent struct {
	ele *list.Element
	// key is the full pool map key: namespace|magicNetwork|addr.
	// MarkDead / cleanup must use this, not the bare host:port.
	key string
}
type addrDialerEntry struct {
	dialer       netproxy.Dialer
	magicNetwork string
	refs         int
}

type h2ConnsPool struct {
	mu           sync.Mutex
	h2ConnsPool  map[string]*lockedList
	h2Conn2Ident map[*http2.ClientConn]*poolIdent
	// addr2Dialer is keyed by bare host:port because http2.ClientConnPool
	// GetClientConn only supplies addr. refs tracks live scoped lists that
	// still need this mapping; cleanup of one namespace must not drop it
	// while another namespace is still using the same host:port.
	addr2Dialer map[string]*addrDialerEntry
}

func newH2ConnsPool() *h2ConnsPool {
	return &h2ConnsPool{
		mu:           sync.Mutex{},
		h2ConnsPool:  make(map[string]*lockedList),
		h2Conn2Ident: make(map[*http2.ClientConn]*poolIdent),
		addr2Dialer:  make(map[string]*addrDialerEntry),
	}
}

func (p *h2ConnsPool) registerAddrToDialerMapping(addr string, dialer netproxy.Dialer, magicNetwork string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retainAddrDialerLocked(addr, dialer, magicNetwork)
}

func (p *h2ConnsPool) retainAddrDialerLocked(addr string, dialer netproxy.Dialer, magicNetwork string) {
	if e, ok := p.addr2Dialer[addr]; ok {
		e.dialer = dialer
		e.magicNetwork = magicNetwork
		e.refs++
		return
	}
	p.addr2Dialer[addr] = &addrDialerEntry{
		dialer:       dialer,
		magicNetwork: magicNetwork,
		refs:         1,
	}
}

func (p *h2ConnsPool) releaseAddrDialerLocked(addr string) {
	e, ok := p.addr2Dialer[addr]
	if !ok {
		return
	}
	e.refs--
	if e.refs <= 0 {
		delete(p.addr2Dialer, addr)
	}
}

func poolKeyBareAddr(key string) string {
	// key is namespace|magicNetwork|addr; addr itself may contain ':'.
	i := strings.IndexByte(key, '|')
	if i < 0 {
		return key
	}
	j := strings.IndexByte(key[i+1:], '|')
	if j < 0 {
		return key
	}
	return key[i+1+j+1:]
}

func (p *h2ConnsPool) acquireConnList(addr string) (*lockedList, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns, cached := p.h2ConnsPool[addr]
	if conns == nil {
		conns = newLockedList()
		p.h2ConnsPool[addr] = conns
	}
	conns.refs++
	return conns, cached
}

func (p *h2ConnsPool) acquireConnListForDialer(key string, addr string, dialer netproxy.Dialer, magicNetwork string) (*lockedList, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns, cached := p.h2ConnsPool[key]
	if conns == nil {
		conns = newLockedList()
		p.h2ConnsPool[key] = conns
		p.retainAddrDialerLocked(addr, dialer, magicNetwork)
	} else {
		// Keep GetClientConn on the latest chain for this host:port.
		if e := p.addr2Dialer[addr]; e != nil {
			e.dialer = dialer
			e.magicNetwork = magicNetwork
		} else {
			p.retainAddrDialerLocked(addr, dialer, magicNetwork)
		}
	}
	conns.refs++
	return conns, cached
}

func (p *h2ConnsPool) releaseConnList(addr string, conns *lockedList) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conns.refs > 0 {
		conns.refs--
	}
	p.cleanupConnListLocked(addr, conns)
}

func (p *h2ConnsPool) cleanupConnListLocked(addr string, conns *lockedList) {
	if conns == nil || p.h2ConnsPool[addr] != conns || conns.refs != 0 {
		return
	}
	conns.mu.Lock()
	empty := conns.l.Len() == 0
	conns.mu.Unlock()
	if !empty {
		return
	}
	delete(p.h2ConnsPool, addr)
	p.releaseAddrDialerLocked(poolKeyBareAddr(addr))
}

func (p *h2ConnsPool) GetUnderlayConn(c *http2.ClientConn) (netproxy.Conn, error) {
	p.mu.Lock()
	ident, ok := p.h2Conn2Ident[c]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("GetUnderlayConn: not found")
	}
	return ident.ele.Value.(*h2Conn).rawConn, nil
}

func (p *h2ConnsPool) GetConn(ctx context.Context, nextDialer netproxy.Dialer, addr string, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	// Key by address + network + the chained dialer's transport namespace:
	// a config reload that swaps the underlying chain must not reuse
	// connections dialed through the previous generation.
	scopeKey := string(netproxy.TransportCacheNamespace(nextDialer)) + "|" + magicNetwork
	fullKey := scopeKey + "|" + addr
	conns, cachedConnsFound := p.acquireConnListForDialer(fullKey, addr, nextDialer, magicNetwork)
	defer p.releaseConnList(fullKey, conns)

	if cachedConnsFound {
		conns.mu.Lock()
		if conns.l.Len() > 0 {
			for p := conns.l.Front(); p != nil; p = p.Next() {
				h2Conn := p.Value.(*h2Conn)
				if h2Conn.h2Conn.CanTakeNewRequest() {
					conns.mu.Unlock()
					return h2Conn.rawConn, h2Conn.h2Conn, nil
				}
			}
		}
		conns.mu.Unlock()
	}

	// New.
	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	defer cancel()
	rawConn, err := nextDialer.DialContext(dialCtx, magicNetwork, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("h2ConnsPool.GetClientConn: %w", err)
	}
	nextProto := ""
	if tlsConn, ok := rawConn.(*tls.Conn); ok {
		if err := netproxy.HandshakeWithContext(dialCtx, tlsConn); err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		return rawConn, nil, nil
	case "h2":
		t := http2.Transport{
			ConnPool:        p,
			IdleConnTimeout: 90 * time.Second,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
		h2clientConn, err := t.NewClientConn(&netproxy.FakeNetConn{
			Conn: rawConn,
		})
		if err != nil {
			return nil, nil, err
		}
		conns.mu.Lock()
		ele := conns.l.PushFront(&h2Conn{
			rawConn: rawConn,
			h2Conn:  h2clientConn,
		})
		conns.mu.Unlock()
		p.mu.Lock()
		p.h2Conn2Ident[h2clientConn] = &poolIdent{
			ele: ele,
			key: fullKey,
		}
		p.mu.Unlock()
		return rawConn, h2clientConn, nil
	default:
		return nil, nil, fmt.Errorf("negotiated unsupported application layer protocol: %v", nextProto)
	}
}

func (p *h2ConnsPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.Lock()
	e, ok := p.addr2Dialer[addr]
	p.mu.Unlock()
	if !ok || e == nil || e.dialer == nil {
		return nil, fmt.Errorf("no valid dialer for h2ConnsPool.GetClientConn")
	}
	_, h2Conn, err := p.GetConn(req.Context(), e.dialer, addr, e.magicNetwork)
	return h2Conn, err
}

func (p *h2ConnsPool) MarkDead(h2c *http2.ClientConn) {
	p.mu.Lock()
	ident, ok := p.h2Conn2Ident[h2c]
	if !ok {
		p.mu.Unlock()
		return
	}
	key := ident.key
	conns := p.h2ConnsPool[key]
	delete(p.h2Conn2Ident, h2c)
	p.mu.Unlock()
	if conns == nil {
		return
	}
	conns.mu.Lock()
	conns.l.Remove(ident.ele)
	conns.mu.Unlock()
	p.mu.Lock()
	p.cleanupConnListLocked(key, conns)
	p.mu.Unlock()
}

var connPool = newH2ConnsPool()
