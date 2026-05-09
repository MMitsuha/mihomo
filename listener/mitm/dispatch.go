package mitm

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/cert"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
)

// Dispatcher decides whether a connection passing through the tunnel should be
// hijacked into the MITM transparent handler. It matches on destination port
// and (optionally) host trie.
type Dispatcher struct {
	opt       *Option
	tunnel    C.Tunnel
	additions []inbound.Addition

	hosts *trie.DomainTrie[struct{}] // nil = match every host
	ports map[uint16]struct{}        // empty = match every port
}

// NewDispatcher builds a dispatcher. ports defaults to {80, 443}; pass an
// empty slice to opt into every port. hosts==nil means "match every host" —
// use that for unconditional hijack of the configured ports.
func NewDispatcher(certCfg *cert.Config, hosts *trie.DomainTrie[struct{}], ports []uint16, tunnel C.Tunnel, handler Handler, additions ...inbound.Addition) *Dispatcher {
	if handler == nil {
		handler = NopHandler{}
	}
	portSet := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		portSet[p] = struct{}{}
	}
	return &Dispatcher{
		opt: &Option{
			APIHost:    "mitm.mihomo",
			CertConfig: certCfg,
			Handler:    handler,
		},
		tunnel:    tunnel,
		additions: additions,
		hosts:     hosts,
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
	if len(d.ports) > 0 {
		if _, ok := d.ports[metadata.DstPort]; !ok {
			return false
		}
	}
	if d.hosts != nil {
		host := metadata.Host
		if host == "" && metadata.DstIP.IsValid() {
			host = metadata.DstIP.String()
		}
		if host == "" {
			return false
		}
		if d.hosts.Search(host) == nil {
			return false
		}
	}
	go HandleConnTransparent(conn, metadata, d.opt, d.tunnel, d.additions...)
	return true
}

// BuildHostsTrie converts a list of host patterns into a domain trie suitable
// for Dispatcher. Returns nil if the slice is empty.
func BuildHostsTrie(patterns []string) (*trie.DomainTrie[struct{}], error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	t := trie.New[struct{}]()
	for _, p := range patterns {
		if err := t.Insert(p, struct{}{}); err != nil {
			return nil, err
		}
	}
	return t, nil
}
