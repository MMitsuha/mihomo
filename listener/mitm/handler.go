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

// prepareRequest fills in Host/scheme on a freshly read HTTP request. It does
// not touch Accept-Encoding — that's a per-rule concern and is constrained
// inside Handler.HandleRequest only when a body rewrite needs to inspect the
// response. Touching it unconditionally here would silently strip br/zstd
// encodings from traffic that no rule is going to rewrite, contradicting the
// "unmatched traffic passes through unchanged" contract in the README.
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
// hop-by-hop headers and (optionally) keep-alive markers. When keepAlive
// is false the response is forced into close-delimited form so a body of
// unknown length still terminates cleanly.
func writeResponse(session *Session, keepAlive bool) error {
	resp := session.Response()
	if resp == nil {
		return ErrInvalidResponse
	}
	removeHopByHopHeaders(resp.Header)
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
		resp.Header.Set("Keep-Alive", "timeout=60")
	} else {
		resp.Header.Set("Connection", "close")
		resp.Header.Del("Keep-Alive")
		resp.Close = true
	}
	return session.writeResponse()
}

// canKeepAlive reports whether the client connection can be reused after
// writing this exchange. We close when:
//   - either side set Close on the message (Connection: close, or upstream
//     reply delimited by EOF — http.ReadResponse populates resp.Close for
//     both),
//   - or the request is older than HTTP/1.1 (we don't do the optional 1.0
//     Keep-Alive negotiation; treating all 1.0 traffic as close avoids the
//     close-delimited body ambiguity that goes with it).
func canKeepAlive(req *http.Request, resp *http.Response) bool {
	if req == nil || resp == nil {
		return false
	}
	if req.Close || resp.Close {
		return false
	}
	if req.ProtoMajor < 1 || (req.ProtoMajor == 1 && req.ProtoMinor < 1) {
		return false
	}
	return true
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
