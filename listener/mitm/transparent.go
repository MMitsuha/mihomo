package mitm

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// HandleConnTransparent processes a connection whose destination is already
// known via metadata, with no HTTP CONNECT envelope. It auto-detects TLS,
// plain HTTP, or other byte streams, applies handlers for the HTTP cases,
// and falls back to raw passthrough for everything else.
//
// Used when a non-MITM inbound (TUN, redir, tproxy, etc.) routes a
// connection into the MITM dispatcher.
func HandleConnTransparent(c net.Conn, target *C.Metadata, opt *Option, filter HostFilter, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer c.Close()

	if opt == nil || opt.CertConfig == nil || target == nil {
		return
	}

	// Re-entrant tunnel calls (passthrough, dialUpstream, parsed-request
	// passthrough) all flow through inbound.NewHTTP, which unconditionally
	// stamps metadata.Type = C.HTTP. Override with the original inbound
	// type so routing rules / IN-TYPE filters / logs see the connection
	// the way the user-configured listener saw it. Done once here so every
	// downstream re-entry inherits it; copy first so we don't mutate the
	// caller's slice.
	adds := make([]inbound.Addition, 0, len(additions)+1)
	adds = append(adds, additions...)
	adds = append(adds, inbound.WithType(target.Type))
	additions = adds

	dst := target.RemoteAddress()
	host := target.Host
	if host == "" && target.DstIP.IsValid() {
		host = target.DstIP.String()
	}

	// Use a bufio big enough to peek the largest legal TLS plaintext
	// fragment (record header + 2^14 bytes). Modern Chrome ClientHellos
	// with PostQuantum extensions can run >4 KiB; the default bufio size
	// would force them down the passthrough path.
	conn := N.NewBufferedConnSize(c, sniPeekBufSize)

	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		log.Debugln("[MITM] %s: set peek deadline: %s", dst, err.Error())
		return
	}
	first, err := conn.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !os.IsTimeout(err) {
		log.Debugln("[MITM] %s: peek first byte: %s", dst, err.Error())
		return
	}
	if len(first) == 0 {
		// Slow client (mobile / satellite) or a server-speaks-first protocol
		// on a MITM-targeted port. Don't drop the connection — fall through
		// to a verbatim relay so whatever protocol it is can still complete.
		log.Debugln("[MITM] %s: empty after peek, passing through", dst)
		passthrough(conn, target, tunnel, additions)
		return
	}

	var (
		tlsState   *tls.ConnectionState
		loopFilter HostFilter // nil if filter has already been resolved here
	)
	if first[0] == 0x16 {
		// Sniff the SNI before terminating. If the user's rules don't target
		// this host, pass through verbatim so we don't fight HSTS-pinned
		// services with our self-signed cert.
		sni, ok := peekSNI(conn, dst)
		if !ok {
			// Couldn't read a usable ClientHello; fall back to passthrough.
			log.Debugln("[MITM] %s: ClientHello unreadable, passing through", dst)
			passthrough(conn, target, tunnel, additions)
			return
		}
		if filter != nil && !filter(sni) {
			log.Debugln("[MITM] %s: SNI=%q not targeted by any rule, passing through", dst, sni)
			passthrough(conn, target, tunnel, additions)
			return
		}

		tlsCfg := opt.CertConfig.NewTLSConfigForHost(host)
		tlsCfg.GetCertificate = wrapCertLogger(tlsCfg.GetCertificate, dst)
		tlsConn := tls.Server(conn, tlsCfg)
		hsCtx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		err := tlsConn.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			// The browser commonly aborts the handshake when it doesn't trust
			// our CA. Surface that explicitly so the symptom isn't a silent
			// "connection reset" with no log line.
			log.Warnln("[MITM] %s: TLS handshake from client failed: %s (is mitm.crt installed as a trusted root?)", dst, err.Error())
			return
		}
		state := tlsConn.ConnectionState()
		tlsState = &state
		conn = N.NewBufferedConn(tlsConn)
		log.Debugln("[MITM] %s: TLS terminated, SNI=%q", dst, state.ServerName)
	} else {
		// peek a few more bytes to confirm HTTP method; otherwise fall back
		// to a raw passthrough (some 80/443 traffic isn't HTTP/HTTPS at all).
		if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
			return
		}
		buf, perr := conn.Peek(7)
		_ = conn.SetReadDeadline(time.Time{})
		if perr != nil && !errors.Is(perr, bufio.ErrBufferFull) && !os.IsTimeout(perr) {
			log.Debugln("[MITM] %s: peek HTTP method: %s", dst, perr.Error())
			return
		}
		if !isHTTPTraffic(buf) {
			log.Debugln("[MITM] %s: not HTTP, passing through", dst)
			passthrough(conn, target, tunnel, additions)
			return
		}
		// Don't apply the filter on metadata host here. Transparent inbounds
		// (TUN, redir, tproxy) deliver only the destination IP — the actual
		// hostname doesn't appear until we read the request's Host header.
		// Pre-filtering on IP would silently disable HTTP MITM for every
		// hostname-shaped rule on those inbounds. Defer to the loop, which
		// inspects req.Host on the first request and falls through to a
		// parsed-request passthrough if the rule set doesn't target it.
		loopFilter = filter
	}

	runTransparentLoop(conn, c, target, opt, tlsState, loopFilter, tunnel, additions)
}

// peekSNI reads enough of the ClientHello (without consuming) to extract SNI.
// Returns ok=false if the ClientHello is malformed or the read times out.
func peekSNI(conn *N.BufferedConn, dst string) (string, bool) {
	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return "", false
	}
	defer conn.SetReadDeadline(time.Time{})

	header, err := conn.Peek(5)
	if err != nil || len(header) < 5 {
		return "", false
	}
	if header[0] != 0x16 {
		return "", false
	}
	recordLen := int(header[3])<<8 | int(header[4])
	// TLSPlaintext.fragment is capped at 2^14 bytes; the 5-byte record
	// header sits on top of that, so the on-wire record can be 16389 bytes.
	if recordLen > 16384 {
		return "", false
	}
	total := 5 + recordLen
	buf, err := conn.Peek(total)
	if err != nil || len(buf) < total {
		return "", false
	}

	sni, err := sniffer.SniffTLS(buf)
	if err != nil || sni == nil {
		log.Debugln("[MITM] %s: SniffTLS failed: %v", dst, err)
		return "", false
	}
	return *sni, true
}

// wrapCertLogger reports the SNI/host actually used for cert minting and any
// failure that prevents the leaf cert from being issued.
func wrapCertLogger(orig func(*tls.ClientHelloInfo) (*tls.Certificate, error), dst string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := orig(hello)
		if err != nil {
			log.Warnln("[MITM] %s: cert mint failed for SNI=%q: %s", dst, hello.ServerName, err.Error())
		}
		return cert, err
	}
}

// passthrough forwards a non-HTTP/non-TLS stream to the metadata destination
// through the tunnel. It marks the new metadata as Intercepted so the tunnel's
// MITM hook doesn't re-enter the dispatcher, and preserves the original
// metadata.Type — otherwise inbound.NewHTTP would re-stamp routing-relevant
// state to HTTP and silently change rule semantics for connections we're
// supposed to leave verbatim.
func passthrough(conn *N.BufferedConn, target *C.Metadata, tunnel C.Tunnel, additions []inbound.Addition) {
	dstAddr := socks5.ParseAddr(target.RemoteAddress())
	if dstAddr == nil {
		return
	}
	left, right := N.Pipe()
	adds := append([]inbound.Addition{}, additions...)
	adds = append(adds, inbound.WithIntercepted(true))
	c, m := inbound.NewHTTP(dstAddr, conn, right, adds...)
	go tunnel.HandleTCPConn(c, m)
	// N.Relay is bidirectional and closes both ends; one call is enough.
	N.Relay(conn, left)
}

func runTransparentLoop(conn *N.BufferedConn, srcConn net.Conn, target *C.Metadata, opt *Option, tlsState *tls.ConnectionState, filter HostFilter, tunnel C.Tunnel, additions []inbound.Addition) {
	var (
		serverConn   *N.BufferedConn
		serverHost   string // upstream host:port currently held by serverConn
		hostFiltered bool   // first request's filter check already ran
	)
	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	hostPort := target.RemoteAddress()

	dst := target.RemoteAddress()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return
		}
		req, err := readRequest(conn.Reader())
		// Clear the request-read deadline before doing anything else; an
		// upgraded WebSocket relay must run without one and a long upstream
		// round-trip must not race the client read clock.
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !os.IsTimeout(err) && !errors.Is(err, http.ErrServerClosed) {
				log.Debugln("[MITM] %s: read request: %s", dst, err.Error())
			}
			return
		}
		req.RemoteAddr = srcConn.RemoteAddr().String()

		if req.Host == "" {
			req.Host = hostPort
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		session := newSession(conn, req)
		prepareRequest(tlsState, req)

		// HTTP-branch deferred filter: now that req.Host is parsed, decide
		// whether this connection is targeted by any rule. If not, hand the
		// already-parsed request off to a tunnelled relay so we don't keep
		// touching its headers per iteration.
		if !hostFiltered && filter != nil && !filter(req.Host) {
			hostFiltered = true
			log.Debugln("[MITM] %s: host=%q not targeted by any rule, passing through", dst, req.Host)
			passthroughParsedRequest(conn, srcConn, req, tunnel, additions)
			return
		}
		hostFiltered = true

		if isWebsocketRequest(req) {
			if serverConn != nil && serverHost != upstreamHostPort(req) {
				_ = serverConn.Close()
				serverConn = nil
			}
			if serverConn == nil {
				serverConn, err = dialUpstream(context.Background(), req, srcConn, tunnel, additions...)
				if err != nil {
					opt.Handler.HandleError(session, err)
					return
				}
				serverHost = upstreamHostPort(req)
			}
			_ = relayWebsocket(conn, serverConn, req)
			return
		}

		newReq, newResp := opt.Handler.HandleRequest(session)
		if newReq != nil {
			session.SetRequest(newReq)
			req = newReq
		}
		if newResp != nil {
			session.SetResponse(newResp)
			// Handler is short-circuiting; if the original request carried a
			// body, the body bytes are still sitting in the bufio reader and
			// we have no upstream to flush them to. Force the connection
			// closed so the next iteration's readRequest doesn't parse those
			// bytes as a malformed request line. Draining instead would be
			// unbounded for chunked / large content-length payloads.
			if requestHasBody(req) {
				newResp.Close = true
			}
			keepAlive := canKeepAlive(req, newResp)
			if err := writeResponse(session, keepAlive); err != nil {
				opt.Handler.HandleError(session, err)
				return
			}
			if !keepAlive {
				_ = closeRequestBody(req)
				return
			}
			continue
		}

		removeHopByHopHeaders(req.Header)
		req.RequestURI = ""

		// Re-dial when the request's effective upstream changes — e.g. a
		// header rewrite rule rewrote `Host`, or a multi-Host plain-HTTP
		// stream is sending requests for different origins.
		if serverConn != nil && serverHost != upstreamHostPort(req) {
			_ = serverConn.Close()
			serverConn = nil
		}
		if serverConn == nil {
			serverConn, err = dialUpstream(context.Background(), req, srcConn, tunnel, additions...)
			if err != nil {
				opt.Handler.HandleError(session, err)
				session.SetResponse(session.NewErrorResponse(err))
				_ = writeResponse(session, false)
				return
			}
			serverHost = upstreamHostPort(req)
		}

		// Bound the upstream round-trip so a wedged origin can't pin the
		// client conn open indefinitely. The deadline covers both the
		// request write and the response header read.
		_ = serverConn.SetWriteDeadline(time.Now().Add(readDeadline))
		if err := req.Write(serverConn); err != nil {
			_ = serverConn.SetWriteDeadline(time.Time{})
			opt.Handler.HandleError(session, err)
			// Surface a 502 so the client sees a parseable error instead of
			// a bare connection reset.
			session.SetResponse(session.NewErrorResponse(err))
			_ = writeResponse(session, false)
			return
		}
		_ = serverConn.SetWriteDeadline(time.Time{})

		_ = serverConn.SetReadDeadline(time.Now().Add(readDeadline))
		resp, err := http.ReadResponse(serverConn.Reader(), req)
		if err != nil {
			_ = serverConn.SetReadDeadline(time.Time{})
			opt.Handler.HandleError(session, err)
			session.SetResponse(session.NewErrorResponse(err))
			_ = writeResponse(session, false)
			return
		}
		// Hold the deadline through body transfer (cleared once the body is
		// fully written to the client) so a wedged origin during body read
		// can't pin both conns indefinitely.
		session.SetResponse(resp)

		if rewritten := opt.Handler.HandleResponse(session); rewritten != nil {
			session.SetResponse(rewritten)
		}

		keepAlive := canKeepAlive(req, session.Response())
		writeErr := writeResponse(session, keepAlive)
		_ = serverConn.SetReadDeadline(time.Time{})
		if writeErr != nil {
			opt.Handler.HandleError(session, writeErr)
			return
		}
		if !keepAlive {
			return
		}
	}
}

// upstreamHostPort returns the host:port that dialUpstream would target for
// req. Used as a cache key so we don't reuse an upstream conn for a request
// whose effective destination changed under us (Host header rewrite, etc.).
func upstreamHostPort(req *http.Request) string {
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "80"
		if req.TLS != nil {
			port = "443"
		}
		addr = net.JoinHostPort(addr, port)
	}
	return addr
}

// requestHasBody reports whether the parsed request carries (or might carry)
// a body that hasn't been consumed yet. Used to decide whether a short-circuit
// response must force-close the connection (since unread body bytes would
// otherwise be parsed as the next request).
func requestHasBody(req *http.Request) bool {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	// ContentLength == 0 is "no body"; -1 is unknown (chunked / close-
	// delimited) and > 0 is a known body. Both of the latter mean we
	// might still have bytes pending on the wire.
	return req.ContentLength != 0
}

// closeRequestBody best-effort closes req.Body. Always safe to call.
func closeRequestBody(req *http.Request) error {
	if req == nil || req.Body == nil {
		return nil
	}
	return req.Body.Close()
}

// passthroughParsedRequest forwards an already-parsed request to upstream and
// then bidirectional-relays the rest of the stream. Used by the HTTP host
// filter when it rejects a request after readRequest has already consumed it
// from the client conn — re-entering tunnelled passthrough at the byte level
// is no longer possible because the request bytes are gone from the client
// conn buffer.
func passthroughParsedRequest(conn *N.BufferedConn, srcConn net.Conn, req *http.Request, tunnel C.Tunnel, additions []inbound.Addition) {
	upstream, err := dialUpstream(context.Background(), req, srcConn, tunnel, additions...)
	if err != nil {
		return
	}
	defer upstream.Close()
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		return
	}
	N.Relay(conn, upstream)
}

