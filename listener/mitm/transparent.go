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
		log.Debugln("[MITM] %s: empty stream", dst)
		return
	}

	var tlsState *tls.ConnectionState
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
	}

	runTransparentLoop(conn, c, target, opt, tlsState, tunnel, additions)
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
	total := 5 + recordLen
	if total > 16384 { // TLS plaintext fragment cap; sanity bound
		return "", false
	}
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
	// N.Relay is bidirectional and closes both ends; one call is enough.
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
			keepAlive := canKeepAlive(req, newResp)
			if err := writeResponse(session, keepAlive); err != nil {
				opt.Handler.HandleError(session, err)
				return
			}
			if !keepAlive {
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
				_ = writeResponse(session, false)
				return
			}
		}

		// Bound the upstream round-trip so a wedged origin can't pin the
		// client conn open indefinitely. The deadline covers both the
		// request write and the response header read.
		_ = serverConn.SetWriteDeadline(time.Now().Add(readDeadline))
		if err := req.Write(serverConn); err != nil {
			_ = serverConn.SetWriteDeadline(time.Time{})
			opt.Handler.HandleError(session, err)
			return
		}
		_ = serverConn.SetWriteDeadline(time.Time{})

		_ = serverConn.SetReadDeadline(time.Now().Add(readDeadline))
		resp, err := http.ReadResponse(serverConn.Reader(), req)
		_ = serverConn.SetReadDeadline(time.Time{})
		if err != nil {
			opt.Handler.HandleError(session, err)
			return
		}
		session.SetResponse(resp)

		if rewritten := opt.Handler.HandleResponse(session); rewritten != nil {
			session.SetResponse(rewritten)
		}

		keepAlive := canKeepAlive(req, session.Response())
		if err := writeResponse(session, keepAlive); err != nil {
			opt.Handler.HandleError(session, err)
			return
		}
		if !keepAlive {
			return
		}
	}
}

