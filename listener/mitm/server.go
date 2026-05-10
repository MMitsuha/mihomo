package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

type Handler interface {
	HandleRequest(*Session) (*http.Request, *http.Response)
	HandleResponse(*Session) *http.Response
	HandleError(*Session, error)
}

type Option struct {
	Authority *ca.MitmAuthority
	Handler   Handler
}

var (
	authorityMux sync.Mutex
	authority    *ca.MitmAuthority
)

func NewOption(handler Handler) (*Option, error) {
	authority, err := DefaultAuthority()
	if err != nil {
		return nil, err
	}
	if handler == nil {
		handler = NoopHandler{}
	}
	return &Option{Authority: authority, Handler: handler}, nil
}

func DefaultAuthority() (*ca.MitmAuthority, error) {
	authorityMux.Lock()
	defer authorityMux.Unlock()
	if authority != nil {
		return authority, nil
	}

	if _, err := os.Stat(C.Path.RootCA()); os.IsNotExist(err) {
		log.Infoln("Can't find mitm_ca.crt, start generate")
		if err = ca.GenerateAndSaveMitmCA(C.Path.RootCA(), C.Path.CAKey()); err != nil {
			return nil, err
		}
		log.Infoln("Generated MITM CA private key and certificate")
	}

	var err error
	authority, err = ca.LoadMitmAuthority(C.Path.RootCA(), C.Path.CAKey())
	return authority, err
}

func RootCAPEM() ([]byte, error) {
	authority, err := DefaultAuthority()
	if err != nil {
		return nil, err
	}
	cert := authority.GetCA()
	if cert == nil {
		return nil, errors.New("MITM CA is unavailable")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

func RootCAX509() (*x509.Certificate, error) {
	authority, err := DefaultAuthority()
	if err != nil {
		return nil, err
	}
	return authority.GetCA(), nil
}

type NoopHandler struct{}

func (NoopHandler) HandleRequest(*Session) (*http.Request, *http.Response) { return nil, nil }
func (NoopHandler) HandleResponse(*Session) *http.Response                 { return nil }
func (NoopHandler) HandleError(*Session, error)                            {}

func sourceAddrFromMetadata(metadata *C.Metadata, fallback net.Addr) net.Addr {
	if metadata.RawSrcAddr != nil {
		return metadata.RawSrcAddr
	}
	if metadata.SrcIP.IsValid() && metadata.SrcPort != 0 {
		return net.TCPAddrFromAddrPort(metadata.SourceAddrPort())
	}
	return fallback
}
