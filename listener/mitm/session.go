package mitm

import (
	"io"
	"net"
	"sync"

	"github.com/metacubex/http"
)

// Session captures one request/response exchange for a Handler.
type Session struct {
	conn     net.Conn
	request  *http.Request
	response *http.Response

	mu    sync.RWMutex
	props map[string]any
}

func newSession(conn net.Conn, req *http.Request) *Session {
	return &Session{
		conn:    conn,
		request: req,
		props:   make(map[string]any),
	}
}

// Request returns the current request. Handlers may mutate the returned value.
func (s *Session) Request() *http.Request { return s.request }

// Response returns the current response. May be nil while the request phase is
// still in flight.
func (s *Session) Response() *http.Response { return s.response }

// SetRequest replaces the in-flight request.
func (s *Session) SetRequest(req *http.Request) { s.request = req }

// SetResponse stores a response. The proxy will write it back to the client.
func (s *Session) SetResponse(resp *http.Response) { s.response = resp }

// Get retrieves a session-scoped property.
func (s *Session) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.props[key]
	return v, ok
}

// Set stores a session-scoped property accessible to chained handlers.
func (s *Session) Set(key string, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.props[key] = val
}

// NewResponse builds a response carrying the supplied body and status code.
func (s *Session) NewResponse(code int, body io.Reader) *http.Response {
	return NewResponse(code, body, s.request)
}

// NewErrorResponse builds a 502 Bad Gateway response advertising err to the client.
func (s *Session) NewErrorResponse(err error) *http.Response {
	return NewErrorResponse(s.request, err)
}

func (s *Session) writeResponse() error {
	if s.response == nil {
		return ErrInvalidResponse
	}
	defer s.response.Body.Close()
	return s.response.Write(s.conn)
}
