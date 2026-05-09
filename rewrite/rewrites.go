package rewrite

import (
	"bytes"
	"io"

	C "github.com/metacubex/mihomo/constant"
)

// Static response bodies used by reject-* rule types.
var (
	EmptyDict   = newBody([]byte("{}"))
	EmptyArray  = newBody([]byte("[]"))
	OnePixelPNG = newBody([]byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
		0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
		0x11, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x62, 0x60, 0x60, 0x60,
		0x00, 0x04, 0x00, 0x00, 0xff, 0xff, 0x00, 0x0f, 0x00, 0x03, 0xfe, 0x8f,
		0xeb, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42,
		0x60, 0x82,
	})
)

// Body provides a fresh ReadCloser per call so the same payload can be served
// to many concurrent requests.
type Body interface {
	Body() io.ReadCloser
	ContentLength() int64
}

type bodyImpl struct {
	data []byte
}

func (b *bodyImpl) Body() io.ReadCloser   { return io.NopCloser(bytes.NewReader(b.data)) }
func (b *bodyImpl) ContentLength() int64  { return int64(len(b.data)) }

func newBody(data []byte) *bodyImpl { return &bodyImpl{data: data} }

// Rules is a request/response pair of rule sets.
type Rules struct {
	request  []C.Rewrite
	response []C.Rewrite
}

func NewRules(req, res []C.Rewrite) *Rules {
	return &Rules{request: req, response: res}
}

// SearchInRequest iterates the request-phase rules and stops on the first do() == true.
func (r *Rules) SearchInRequest(do func(C.Rewrite) bool) bool {
	for _, rule := range r.request {
		if do(rule) {
			return true
		}
	}
	return false
}

// SearchInResponse iterates the response-phase rules and stops on the first do() == true.
func (r *Rules) SearchInResponse(do func(C.Rewrite) bool) bool {
	for _, rule := range r.response {
		if do(rule) {
			return true
		}
	}
	return false
}

var _ C.RewriteRule = (*Rules)(nil)
