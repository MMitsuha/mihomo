package mitm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

func HandleConn(c net.Conn, metadata *C.Metadata, tunnel C.Tunnel, opt *Option) {
	if opt == nil {
		_ = c.Close()
		return
	}

	var (
		sourceAddr = sourceAddrFromMetadata(metadata, c.RemoteAddr())
		serverConn *N.BufferedConn
		connState  *tls.ConnectionState
	)

	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	conn := N.NewBufferedConn(c)
	var err error
	conn, connState, err = prepareClientConn(conn, metadata, opt)
	if err != nil {
		handleError(opt, nil, err)
		_ = conn.Close()
		return
	}

	if !isBufferedHTTP(conn) {
		request := rawRelayRequest(metadata, connState)
		serverConn, err = getServerConn(serverConn, request, sourceAddr, metadata, tunnel)
		if err == nil {
			N.Relay(serverConn, conn)
		} else {
			handleError(opt, newSession(conn, request, nil), err)
		}
		return
	}

	for {
		if err = conn.SetReadDeadline(time.Now().Add(65 * time.Second)); err != nil {
			break
		}

		request, err := http.ReadRequest(conn.Reader())
		if err != nil {
			break
		}

		session := newSession(conn, request, nil)
		request.RemoteAddr = sourceAddr.String()
		prepareRequest(connState, request, metadata)

		if request.Method == http.MethodConnect {
			if err = handleConnect(session); err != nil {
				handleError(opt, session, err)
				break
			}
			continue
		}

		if isCertificateRequest(request) {
			if err = handleCertificateRequest(session); err != nil {
				handleError(opt, session, err)
			}
			continue
		}

		removeHopByHopHeaders(request.Header)
		removeExtraHTTPHostPort(request)

		newReq, newRes := opt.Handler.HandleRequest(session)
		if newReq != nil {
			session.request = newReq
			request = newReq
		}
		if newRes != nil {
			session.response = newRes
			if err = writeResponse(session, false); err != nil {
				handleError(opt, session, err)
				break
			}
			continue
		}

		request.RequestURI = ""
		if request.URL.Host == "" {
			session.response = session.NewErrorResponse(ErrInvalidURL)
		} else {
			serverConn, err = getServerConn(serverConn, request, sourceAddr, metadata, tunnel)
			if err != nil {
				session.response = session.NewErrorResponse(err)
			} else if err = request.Write(serverConn); err != nil {
				session.response = session.NewErrorResponse(err)
			} else {
				session.response, err = http.ReadResponse(serverConn.Reader(), request)
				if err != nil {
					session.response = session.NewErrorResponse(err)
				}
			}
		}

		if err = writeResponseWithHandler(session, opt, !session.response.Close); err != nil {
			handleError(opt, session, err)
			break
		}

		if isWebsocketRequest(request) && session.response.StatusCode == http.StatusSwitchingProtocols {
			N.Relay(serverConn, conn)
			return
		}
	}

	_ = conn.Close()
}

func prepareClientConn(conn *N.BufferedConn, metadata *C.Metadata, opt *Option) (*N.BufferedConn, *tls.ConnectionState, error) {
	_ = conn.SetReadDeadline(time.Now().Add(C.DefaultTLSTimeout))
	b, err := conn.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return conn, nil, err
	}
	if b[0] != 0x16 {
		return conn, nil, nil
	}

	tlsConn := tls.Server(conn, opt.Authority.NewTLSConfigForHost(metadata.String()))
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return conn, nil, fmt.Errorf("handshake failed: %w", err)
	}

	cs := tlsConn.ConnectionState()
	return N.NewBufferedConn(tlsConn), &cs, nil
}

func isBufferedHTTP(conn *N.BufferedConn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf, err := conn.Peek(7)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && err != bufio.ErrBufferFull && !os.IsTimeout(err) {
		return false
	}
	return isHTTPTraffic(buf)
}

func rawRelayRequest(metadata *C.Metadata, connState *tls.ConnectionState) *http.Request {
	scheme := "http"
	if connState != nil {
		scheme = "https"
	}
	requestURL := &url.URL{Scheme: scheme, Host: metadata.RemoteAddress()}
	return &http.Request{
		Method: http.MethodConnect,
		URL:    requestURL,
		Host:   requestURL.Host,
		Header: http.Header{},
		TLS:    connState,
	}
}

func prepareRequest(connState *tls.ConnectionState, request *http.Request, metadata *C.Metadata) {
	host := request.Header.Get("Host")
	if host != "" {
		request.Host = host
	}
	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}
	if request.URL.Host == "" {
		request.URL.Host = metadata.RemoteAddress()
		request.Host = request.URL.Host
	}

	if request.URL.Scheme == "" {
		request.URL.Scheme = "http"
	}
	if connState != nil {
		request.TLS = connState
		request.URL.Scheme = "https"
	}

	if request.Header.Get("Accept-Encoding") != "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
}

func handleConnect(session *Session) error {
	if session.request.ProtoMajor > 1 {
		session.request.ProtoMajor = 1
		session.request.ProtoMinor = 1
	}
	_, err := fmt.Fprintf(session.conn, "HTTP/%d.%d %03d %s\r\n\r\n", session.request.ProtoMajor, session.request.ProtoMinor, http.StatusOK, "Connection established")
	return err
}

func isCertificateRequest(request *http.Request) bool {
	host := strings.ToLower(request.URL.Hostname())
	if host != "mitm.mihomo" && host != "mitm.clash" {
		return false
	}
	return strings.EqualFold(request.URL.Path, "/cert.crt")
}

func handleCertificateRequest(session *Session) error {
	b, err := RootCAPEM()
	if err != nil {
		return err
	}

	session.response = session.NewResponse(http.StatusOK, bytes.NewReader(b))
	session.response.Close = true
	session.response.Header.Set("Content-Type", "application/x-x509-ca-cert")
	session.response.ContentLength = int64(len(b))
	session.response.Header.Set("Content-Length", fmt.Sprintf("%d", len(b)))
	return session.writeResponse()
}

func writeResponseWithHandler(session *Session, opt *Option, keepAlive bool) error {
	if res := opt.Handler.HandleResponse(session); res != nil {
		session.response = res
	}
	return writeResponse(session, keepAlive)
}

func writeResponse(session *Session, keepAlive bool) error {
	if session.response == nil {
		return ErrInvalidResponse
	}

	removeHopByHopHeaders(session.response.Header)
	if keepAlive && !session.response.Close {
		session.response.Header.Set("Connection", "keep-alive")
		session.response.Header.Set("Keep-Alive", "timeout=60")
	}

	return session.writeResponse()
}

func handleError(opt *Option, session *Session, err error) {
	if session != nil && session.response != nil && session.response.Body != nil {
		defer func() {
			_, _ = io.Copy(io.Discard, session.response.Body)
			_ = session.response.Body.Close()
		}()
	}
	opt.Handler.HandleError(session, err)
}
