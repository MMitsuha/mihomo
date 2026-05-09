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
	C "github.com/metacubex/mihomo/constant"
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
func HandleConnTransparent(c net.Conn, target *C.Metadata, opt *Option, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer c.Close()

	if opt == nil || opt.CertConfig == nil || target == nil {
		return
	}

	conn := N.NewBufferedConn(c)

	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return
	}
	first, err := conn.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !os.IsTimeout(err) {
		return
	}
	if len(first) == 0 {
		return
	}

	host := target.Host
	if host == "" && target.DstIP.IsValid() {
		host = target.DstIP.String()
	}

	var tlsState *tls.ConnectionState
	if first[0] == 0x16 {
		tlsConn := tls.Server(conn, opt.CertConfig.NewTLSConfigForHost(host))
		hsCtx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		err := tlsConn.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			return
		}
		state := tlsConn.ConnectionState()
		tlsState = &state
		conn = N.NewBufferedConn(tlsConn)
	} else {
		// peek a few more bytes to confirm HTTP method; otherwise fall back
		// to a raw passthrough (some 80/443 traffic isn't HTTP/HTTPS at all).
		if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
			return
		}
		buf, perr := conn.Peek(7)
		_ = conn.SetReadDeadline(time.Time{})
		if perr != nil && !errors.Is(perr, bufio.ErrBufferFull) && !os.IsTimeout(perr) {
			return
		}
		if !isHTTPTraffic(buf) {
			passthrough(conn, target, tunnel, additions)
			return
		}
	}

	runTransparentLoop(conn, c, target, opt, tlsState, tunnel, additions)
}

// passthrough forwards a non-HTTP/non-TLS stream to the metadata destination
// through the tunnel. It marks the new metadata as Intercepted so the tunnel's
// MITM hook doesn't re-enter the dispatcher.
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
	go N.Relay(left, conn)
	N.Relay(conn, left)
}

func runTransparentLoop(conn *N.BufferedConn, srcConn net.Conn, target *C.Metadata, opt *Option, tlsState *tls.ConnectionState, tunnel C.Tunnel, additions []inbound.Addition) {
	var serverConn *N.BufferedConn
	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	hostPort := target.RemoteAddress()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return
		}
		req, err := readRequest(conn.Reader())
		if err != nil {
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

		if isWebsocketRequest(req) {
			if serverConn == nil {
				serverConn, err = dialUpstream(context.Background(), req, srcConn, tunnel, additions...)
				if err != nil {
					opt.Handler.HandleError(session, err)
					return
				}
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
			if err := writeResponse(session, false); err != nil {
				opt.Handler.HandleError(session, err)
				return
			}
			continue
		}

		removeHopByHopHeaders(req.Header)
		req.RequestURI = ""

		if serverConn == nil {
			serverConn, err = dialUpstream(context.Background(), req, srcConn, tunnel, additions...)
			if err != nil {
				opt.Handler.HandleError(session, err)
				session.SetResponse(session.NewErrorResponse(err))
				_ = writeResponse(session, true)
				return
			}
		}

		if err := req.Write(serverConn); err != nil {
			opt.Handler.HandleError(session, err)
			return
		}

		resp, err := http.ReadResponse(serverConn.Reader(), req)
		if err != nil {
			opt.Handler.HandleError(session, err)
			return
		}
		session.SetResponse(resp)

		if rewritten := opt.Handler.HandleResponse(session); rewritten != nil {
			session.SetResponse(rewritten)
		}

		if err := writeResponse(session, true); err != nil {
			opt.Handler.HandleError(session, err)
			return
		}
	}
}

