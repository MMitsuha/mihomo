package mitm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

const (
	readDeadline = 65 * time.Second
	peekDeadline = time.Second
)

// HandleConn drives a single client connection. It demultiplexes plain HTTP,
// CONNECT-tunnelled HTTPS, websockets and other-protocol-over-CONNECT, optionally
// applying handler hooks for rewriting.
func HandleConn(c net.Conn, opt *Option, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	defer c.Close()

	addrPort, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	clientIP := addrPort.Addr()

	authenticator := store.Authenticator()
	trusted := authenticator == nil || clientIP.IsLoopback() || clientIP.IsUnspecified()

	conn := N.NewBufferedConn(c)
	var (
		serverConn *N.BufferedConn
		sourceAddr net.Addr = c.RemoteAddr()
		tlsState   *tls.ConnectionState
	)
	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return
		}

		req, err := readRequest(conn.Reader())
		if err != nil {
			return
		}
		req.RemoteAddr = sourceAddr.String()

		session := newSession(conn, req)

		if !trusted {
			if !checkAuth(req, authenticator) {
				resp := unauthorizedResponse(req)
				resp.Close = true
				session.SetResponse(resp)
				_ = session.writeResponse()
				return
			}
			trusted = true
		}

		if req.Method == http.MethodConnect {
			next, err := handleConnect(conn, session, opt, tunnel, additions)
			if err != nil {
				opt.Handler.HandleError(session, err)
				return
			}
			switch next.kind {
			case connectClose:
				return
			case connectRelay:
				return // hijacked
			case connectTLS:
				conn = next.conn
				tlsState = next.tlsState
				continue
			case connectPlain:
				continue
			}
		}

		prepareRequest(tlsState, req)

		// CA / API endpoint, e.g. http://mitm.mihomo/cert.crt
		if req.URL.Hostname() == opt.APIHost {
			if err := handleAPIRequest(session, opt); err != nil {
				opt.Handler.HandleError(session, err)
			}
			return
		}

		if isWebsocketRequest(req) {
			if serverConn == nil {
				serverConn, err = dialUpstream(context.Background(), req, c, tunnel, additions...)
				if err != nil {
					opt.Handler.HandleError(session, err)
					return
				}
			}
			if err := relayWebsocket(conn, serverConn, req); err != nil {
				opt.Handler.HandleError(session, err)
			}
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

		if req.URL.Host == "" {
			session.SetResponse(session.NewErrorResponse(ErrInvalidURL))
			_ = writeResponse(session, true)
			continue
		}

		if serverConn == nil {
			serverConn, err = dialUpstream(context.Background(), req, c, tunnel, additions...)
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

type connectAction int

const (
	connectClose connectAction = iota
	connectRelay
	connectTLS
	connectPlain
)

type connectResult struct {
	kind     connectAction
	conn     *N.BufferedConn
	tlsState *tls.ConnectionState
}

// handleConnect processes a CONNECT request: write the 200 response, optionally
// terminate TLS, and detect non-HTTP traffic that should be relayed verbatim.
func handleConnect(conn *N.BufferedConn, session *Session, opt *Option, tunnel C.Tunnel, additions []inbound.Addition) (connectResult, error) {
	req := session.Request()
	if req.ProtoMajor > 1 {
		req.ProtoMajor = 1
		req.ProtoMinor = 1
	}
	if _, err := fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", req.ProtoMajor, req.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
		return connectResult{kind: connectClose}, err
	}

	host := req.URL.Host
	if strings.HasSuffix(host, ":80") {
		return connectResult{kind: connectPlain}, nil
	}

	peek, err := conn.Peek(1)
	if err != nil {
		return connectResult{kind: connectClose}, err
	}

	if peek[0] != 0x16 {
		// not TLS — try forwarding raw bytes through the tunnel
		return relayRaw(conn, req, tunnel, additions)
	}

	tlsConn := tls.Server(conn, opt.CertConfig.NewTLSConfigForHost(req.URL.Hostname()))
	hsCtx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	err = tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		session.SetResponse(session.NewErrorResponse(fmt.Errorf("mitm: TLS handshake failed: %w", err)))
		_ = writeResponse(session, false)
		return connectResult{kind: connectClose}, err
	}

	state := tlsConn.ConnectionState()
	bufConn := N.NewBufferedConn(tlsConn)

	if strings.HasSuffix(host, ":443") {
		return connectResult{kind: connectTLS, conn: bufConn, tlsState: &state}, nil
	}

	// non-443 TLS — peek to decide between HTTP and other protocols
	if err := bufConn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return connectResult{kind: connectClose}, err
	}
	buf, err := bufConn.Peek(7)
	_ = bufConn.SetReadDeadline(time.Time{})
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !os.IsTimeout(err) {
		return connectResult{kind: connectClose}, err
	}

	if !isHTTPTraffic(buf) {
		req.TLS = &state
		serverConn, err := dialUpstream(context.Background(), req, conn, tunnel, additions...)
		if err != nil {
			return connectResult{kind: connectClose}, err
		}
		go N.Relay(serverConn, bufConn)
		N.Relay(bufConn, serverConn)
		return connectResult{kind: connectRelay}, nil
	}

	return connectResult{kind: connectTLS, conn: bufConn, tlsState: &state}, nil
}

// relayRaw forwards a non-TLS, non-HTTP byte stream that arrived after a CONNECT.
func relayRaw(conn *N.BufferedConn, req *http.Request, tunnel C.Tunnel, additions []inbound.Addition) (connectResult, error) {
	serverConn, err := dialUpstream(context.Background(), req, conn, tunnel, additions...)
	if err != nil {
		return connectResult{kind: connectClose}, err
	}
	go N.Relay(serverConn, conn)
	N.Relay(conn, serverConn)
	return connectResult{kind: connectRelay}, nil
}

// relayWebsocket bridges a WebSocket upgrade exchange between client and upstream.
func relayWebsocket(client, upstream *N.BufferedConn, req *http.Request) error {
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		return err
	}
	resp, err := http.ReadResponse(upstream.Reader(), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := resp.Write(client); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}
	go N.Relay(upstream, client)
	N.Relay(client, upstream)
	return nil
}

func writeResponse(session *Session, keepAlive bool) error {
	resp := session.Response()
	if resp == nil {
		return ErrInvalidResponse
	}
	removeHopByHopHeaders(resp.Header)
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
		resp.Header.Set("Keep-Alive", "timeout=60")
	}
	return session.writeResponse()
}

func handleAPIRequest(session *Session, opt *Option) error {
	req := session.Request()
	if opt.CertConfig != nil && strings.EqualFold(req.URL.Path, "/cert.crt") {
		body := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: opt.CertConfig.CA().Raw,
		})
		resp := session.NewResponse(http.StatusOK, bytes.NewReader(body))
		resp.Close = true
		resp.Header.Set("Content-Type", "application/x-x509-ca-cert")
		resp.ContentLength = int64(len(body))
		session.SetResponse(resp)
		return session.writeResponse()
	}

	if opt.Handler.HandleAPIRequest(session) {
		return nil
	}

	body := fmt.Sprintf(`<!DOCTYPE HTML>
<html><head><title>mihomo MITM Proxy - 404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL %q was not found on this server.</p></body>
</html>
`, req.URL.Path)

	resp := session.NewResponse(http.StatusNotFound, strings.NewReader(body))
	resp.Close = true
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.ContentLength = int64(len(body))
	session.SetResponse(resp)
	return session.writeResponse()
}

func prepareRequest(tlsState *tls.ConnectionState, req *http.Request) {
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if tlsState != nil {
		req.TLS = tlsState
		req.URL.Scheme = "https"
	}
	if req.Header.Get("Accept-Encoding") != "" {
		// keep only encodings we can decode
		req.Header.Set("Accept-Encoding", "gzip")
	}
}

func removeHopByHopHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailers")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
	conn := h.Get("Connection")
	h.Del("Connection")
	if conn == "" {
		return
	}
	for _, p := range splitTrim(conn, ",") {
		h.Del(p)
	}
}

func checkAuth(req *http.Request, authenticator auth.Authenticator) bool {
	if authenticator == nil {
		return true
	}
	credential := req.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if len(credential) <= len(prefix) || !strings.EqualFold(credential[:len(prefix)], prefix) {
		return false
	}
	user, pass, err := decodeBasic(credential[len(prefix):])
	if err != nil {
		return false
	}
	if !authenticator.Verify(user, pass) {
		log.Infoln("[MITM] auth failed from %s", req.RemoteAddr)
		return false
	}
	return true
}

func decodeBasic(credential string) (string, string, error) {
	plain, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return "", "", err
	}
	user, pass, ok := strings.Cut(string(plain), ":")
	if !ok {
		return "", "", errors.New("mitm: invalid basic credential")
	}
	return user, pass, nil
}

func unauthorizedResponse(req *http.Request) *http.Response {
	resp := NewResponse(http.StatusProxyAuthRequired, nil, req)
	resp.Header.Set("Proxy-Authenticate", `Basic realm="mihomo MITM"`)
	return resp
}
