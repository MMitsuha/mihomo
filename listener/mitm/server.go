package mitm

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/cert"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
)

// Option configures the MITM listener.
type Option struct {
	Addr       string
	APIHost    string
	CertConfig *cert.Config
	Handler    Handler
}

// Listener accepts MITM client connections.
type Listener struct {
	*Option

	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener.
func (l *Listener) RawAddress() string { return l.addr }

// Address implements C.Listener.
func (l *Listener) Address() string { return l.listener.Addr().String() }

// Close implements C.Listener.
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

// New creates a MITM listener bound to addr.
func New(addr string, certConfig *cert.Config, handler Handler, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: authStore.Default}, certConfig, handler, tunnel, additions...)
}

// NewWithAuthenticate is preserved for parity with other listeners; pass false
// to disable proxy authentication entirely.
func NewWithAuthenticate(addr string, certConfig *cert.Config, handler Handler, tunnel C.Tunnel, authenticate bool, additions ...inbound.Addition) (*Listener, error) {
	store := authStore.Default
	if !authenticate {
		store = authStore.Nil
	}
	return NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: store}, certConfig, handler, tunnel, additions...)
}

// NewWithConfig is the canonical constructor.
func NewWithConfig(config LC.AuthServer, certConfig *cert.Config, handler Handler, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if handler == nil {
		handler = NopHandler{}
	}
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MITM"),
			inbound.WithSpecialRules(""),
		}
	}

	tcp, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	hl := &Listener{
		listener: tcp,
		addr:     config.Listen,
		Option: &Option{
			Addr:       config.Listen,
			APIHost:    "mitm.mihomo",
			CertConfig: certConfig,
			Handler:    handler,
		},
	}

	go func() {
		for {
			c, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					return
				}
				continue
			}

			store := config.AuthStore
			if isDefault || store == authStore.Default {
				if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
					_ = c.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
					store = authStore.Nil
				}
			}
			if store == nil {
				store = authStore.Nil
			}
			go HandleConn(c, hl.Option, tunnel, store, additions...)
		}
	}()

	return hl, nil
}

