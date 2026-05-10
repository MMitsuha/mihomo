package inbound

import (
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// NewMitm receives an intercepted MITM request and returns metadata for the upstream leg.
func NewMitm(target socks5.Addr, source net.Addr, userAgent string, conn net.Conn, additions ...Addition) (net.Conn, *C.Metadata) {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = C.MITM
	metadata.UserAgent = userAgent
	metadata.RawSrcAddr = source
	metadata.RawDstAddr = conn.LocalAddr()
	ApplyAdditions(metadata, WithSrcAddr(source), WithInAddr(conn.LocalAddr()))
	ApplyAdditions(metadata, additions...)
	return conn, metadata
}
