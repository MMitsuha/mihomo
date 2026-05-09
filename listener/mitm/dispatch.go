package mitm

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/cert"
	C "github.com/metacubex/mihomo/constant"
)

// Dispatcher decides whether a connection passing through the tunnel should be
// hijacked into the MITM transparent handler. It matches purely on destination
// port; the user controls scope by choosing which ports to enable, and the
// rewrite rules' URL regexes pick out the URLs that actually get rewritten.
type Dispatcher struct {
	opt       *Option
	tunnel    C.Tunnel
	additions []inbound.Addition

	ports map[uint16]struct{} // empty = no MITM
}

// NewDispatcher builds a dispatcher for the given port set. handler may be
// nil for a transparent passthrough that just decrypts but doesn't rewrite.
func NewDispatcher(certCfg *cert.Config, ports []uint16, tunnel C.Tunnel, handler Handler, additions ...inbound.Addition) *Dispatcher {
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
	}
}

// Dispatch is the function passed to tunnel.SetMitmIntercept. Returns true if
// the connection has been claimed (a goroutine has taken ownership of conn);
// the tunnel must not touch it further.
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
	go HandleConnTransparent(conn, metadata, d.opt, d.tunnel, d.additions...)
	return true
}
