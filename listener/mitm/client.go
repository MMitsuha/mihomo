package mitm

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

func getServerConn(serverConn *N.BufferedConn, request *http.Request, source net.Addr, baseMetadata *C.Metadata, tunnel C.Tunnel) (*N.BufferedConn, error) {
	if serverConn != nil {
		return serverConn, nil
	}

	address := request.URL.Host
	if address == "" {
		address = baseMetadata.RemoteAddress()
	}
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
	go tunnel.HandleTCPConn(inbound.NewMitm(dstAddr, source, request.Header.Get("User-Agent"), right, mitmAdditions(baseMetadata)...))

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

func mitmAdditions(metadata *C.Metadata) []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(metadata.InName),
		inbound.WithInUser(metadata.InUser),
		inbound.WithSpecialProxy(metadata.SpecialProxy),
		inbound.WithSpecialRules(metadata.SpecialRules),
		inbound.WithDSCP(metadata.DSCP),
	}
}
