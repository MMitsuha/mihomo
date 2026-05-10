package mitm

import (
	"context"
	"net"
	"net/url"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type mitmUserAgentContextKey struct{}

func newServerTransport(source net.Addr, baseMetadata *C.Metadata, tunnel C.Tunnel) (*http.Transport, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			userAgent, _ := ctx.Value(mitmUserAgentContextKey{}).(string)
			return newTunnelConn(ctx, address, source, baseMetadata, tunnel, userAgent)
		},
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		Proxy:               nil,
		TLSHandshakeTimeout: C.DefaultTLSTimeout,
	}, nil
}

func getServerConn(serverConn *N.BufferedConn, request *http.Request, source net.Addr, baseMetadata *C.Metadata, tunnel C.Tunnel) (*N.BufferedConn, error) {
	if serverConn != nil {
		return serverConn, nil
	}

	address := serverAddress(request, baseMetadata)
	left, err := newTunnelConn(context.Background(), address, source, baseMetadata, tunnel, request.Header.Get("User-Agent"))
	if err != nil {
		return nil, err
	}

	if request.TLS == nil {
		return N.NewBufferedConn(left), nil
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		_ = left.Close()
		return nil, err
	}
	tlsConfig.ServerName = request.TLS.ServerName
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = request.URL.Hostname()
	}

	tlsConn := tls.Client(left, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = left.Close()
		return nil, err
	}

	return N.NewBufferedConn(tlsConn), nil
}

func serverAddress(request *http.Request, baseMetadata *C.Metadata) string {
	address := request.URL.Host
	if address == "" {
		address = request.Host
	}
	if address == "" {
		address = baseMetadata.RemoteAddress()
	}

	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if (request.URL != nil && request.URL.Scheme == "https") || request.TLS != nil {
			port = "443"
		}
		address = net.JoinHostPort(address, port)
	}
	return address
}

func newTunnelConn(ctx context.Context, address string, source net.Addr, baseMetadata *C.Metadata, tunnel C.Tunnel, userAgent string) (net.Conn, error) {
	address = addressForTunnel(address)
	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return nil, socks5.ErrAddressNotSupported
	}

	left, right := N.Pipe()
	go tunnel.HandleTCPConn(inbound.NewMitm(dstAddr, source, userAgent, right, mitmAdditions(baseMetadata)...))

	select {
	case <-ctx.Done():
		_ = left.Close()
		return nil, ctx.Err()
	default:
	}
	return left, nil
}

func addressForTunnel(address string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	if u, err := url.Parse(address); err == nil && u.Host != "" {
		address = u.Host
	}
	return address
}

func mitmAdditions(metadata *C.Metadata) []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(metadata.InName),
		inbound.WithInUser(metadata.InUser),
		inbound.WithSpecialProxy(metadata.SpecialProxy),
		inbound.WithSpecialRules(metadata.SpecialRules),
		inbound.WithDSCP(metadata.DSCP),
	}
}
