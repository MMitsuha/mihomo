package mitm

import (
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/cert"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// Option bundles the cert config and per-request handler used by the
// transparent dispatcher. It carries no listener state.
type Option struct {
	CertConfig *cert.Config
	Handler    Handler
}

// Handler hooks into request and response phases of an intercepted exchange.
//
// HandleRequest may return:
//   - (newReq, nil)       — replace the upstream request, continue normally.
//   - (nil,    response)  — short-circuit and write `response` back to the client.
//   - (nil,    nil)       — leave the request unchanged and continue.
type Handler interface {
	HandleRequest(*Session) (*http.Request, *http.Response)
	HandleResponse(*Session) *http.Response
	HandleError(*Session, error)
}

// NopHandler is a Handler that performs no rewriting.
type NopHandler struct{}

func (NopHandler) HandleRequest(*Session) (*http.Request, *http.Response) { return nil, nil }
func (NopHandler) HandleResponse(*Session) *http.Response                 { return nil }
func (NopHandler) HandleError(*Session, error)                            {}

// prepareRequest fills in Host/scheme on a freshly read HTTP request.
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
		req.Header.Set("Accept-Encoding", "gzip")
	}
}

// removeHopByHopHeaders strips connection-scoped fields per RFC 7230 §6.1.
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
	for _, p := range strings.Split(conn, ",") {
		h.Del(strings.TrimSpace(p))
	}
}

// writeResponse writes session.Response back to the client, normalising
// hop-by-hop headers and (optionally) keep-alive markers.
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
