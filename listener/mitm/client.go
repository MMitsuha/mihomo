package mitm

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// dialUpstream opens a tunnelled connection to the request's host through the
// engine's tunnel. If the original connection was TLS, an outbound TLS
// handshake is performed using the SNI captured during interception.
func dialUpstream(ctx context.Context, request *http.Request, srcConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) (*N.BufferedConn, error) {
	address := request.URL.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if request.TLS != nil {
			port = "443"
		}
		address = net.JoinHostPort(address, port)
	}

	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return nil, socks5.ErrAddressNotSupported
	}

	left, right := N.Pipe()
	additions = append(additions, inbound.WithIntercepted(true))
	conn, metadata := inbound.NewHTTP(dstAddr, srcConn, right, additions...)
	go tunnel.HandleTCPConn(conn, metadata)

	if request.TLS == nil {
		return N.NewBufferedConn(left), nil
	}

	tlsConn := tls.Client(left, &tls.Config{
		ServerName: request.TLS.ServerName,
		// Pin ALPN to http/1.1 so an h2-capable upstream can't negotiate
		// HTTP/2 — our loop only speaks HTTP/1.1.
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: false,
	})
	hsCtx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = left.Close()
		return nil, err
	}
	return N.NewBufferedConn(tlsConn), nil
}
