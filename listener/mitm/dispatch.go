package mitm

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/cert"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// HostFilter decides whether a destination host (SNI for HTTPS, Host header
// for HTTP) is worth MITM-ing. Returning false makes the dispatcher pass the
// connection through verbatim, so untrusted-CA / pinned hosts don't fail
// loudly with a TLS handshake error.
type HostFilter func(host string) bool

// Dispatcher decides whether a connection passing through the tunnel should be
// hijacked into the MITM transparent handler. It matches on destination port,
// then (optionally) on SNI/Host via HostFilter.
type Dispatcher struct {
	opt       *Option
	tunnel    C.Tunnel
	additions []inbound.Addition

	ports  map[uint16]struct{} // empty = no MITM
	filter HostFilter          // nil = MITM every host on a matching port
}

// NewDispatcher builds a dispatcher for the given port set. handler may be
// nil for a transparent passthrough that just decrypts but doesn't rewrite.
// filter may be nil to MITM every host on a matching port.
func NewDispatcher(certCfg *cert.Config, ports []uint16, filter HostFilter, tunnel C.Tunnel, handler Handler, additions ...inbound.Addition) *Dispatcher {
	if handler == nil {
		handler = NopHandler{}
	}
	portSet := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		portSet[p] = struct{}{}
	}
	return &Dispatcher{
		opt: &Option{
			CertConfig: certCfg,
			Handler:    handler,
		},
		tunnel:    tunnel,
		additions: additions,
		ports:     portSet,
		filter:    filter,
	}
}

// Dispatch is the function passed to tunnel.SetMitmIntercept. Returns true if
// the connection was handled by MITM; the tunnel must not touch it further.
//
// Dispatch runs the transparent handler synchronously because some inbounds
// (sing-tun, sing-vmess, ...) close the conn the moment HandleTCPConn returns.
// Spawning a goroutine here would race the inbound's close path.
func (d *Dispatcher) Dispatch(conn net.Conn, metadata *C.Metadata) bool {
	if d == nil || conn == nil || metadata == nil {
		return false
	}
	if metadata.Intercepted {
		return false
	}
	if metadata.NetWork != C.TCP {
		return false
	}
	// Skip mihomo's own outbound traffic (rule-provider fetches, geo updates,
	// the dashboard zip, DoH queries, etc.). These verify against the system
	// trust store, not the MITM CA, so intercepting them would always fail.
	if metadata.Type == C.INNER {
		return false
	}
	if _, ok := d.ports[metadata.DstPort]; !ok {
		return false
	}
	log.Debugln("[MITM] hijack %s -> %s", metadata.SourceAddress(), metadata.RemoteAddress())
	HandleConnTransparent(conn, metadata, d.opt, d.filter, d.tunnel, d.additions...)
	return true
}
