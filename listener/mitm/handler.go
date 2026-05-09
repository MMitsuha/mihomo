package mitm

import (
	"github.com/metacubex/http"
)

// Handler hooks into request and response phases of an intercepted exchange.
//
// HandleRequest may return:
//   - (newReq, nil)       — replace the upstream request, continue normally.
//   - (nil,    response)  — short-circuit and write `response` back to the client.
//   - (nil,    nil)       — leave the request unchanged and continue.
type Handler interface {
	HandleRequest(*Session) (*http.Request, *http.Response)
	HandleResponse(*Session) *http.Response
	HandleAPIRequest(*Session) bool
	HandleError(*Session, error)
}

// NopHandler is a Handler that performs no rewriting.
type NopHandler struct{}

func (NopHandler) HandleRequest(*Session) (*http.Request, *http.Response) { return nil, nil }
func (NopHandler) HandleResponse(*Session) *http.Response                 { return nil }
func (NopHandler) HandleAPIRequest(*Session) bool                         { return false }
func (NopHandler) HandleError(*Session, error)                            {}
