package mitm

import (
	"testing"

	"github.com/metacubex/http"
)

func TestCanKeepAlive(t *testing.T) {
	httpReq := func(major, minor int, close bool) *http.Request {
		return &http.Request{ProtoMajor: major, ProtoMinor: minor, Close: close}
	}
	httpResp := func(close bool) *http.Response {
		return &http.Response{Close: close}
	}

	cases := []struct {
		name string
		req  *http.Request
		resp *http.Response
		want bool
	}{
		{"nil req", nil, httpResp(false), false},
		{"nil resp", httpReq(1, 1, false), nil, false},
		{"http/1.1 both open", httpReq(1, 1, false), httpResp(false), true},
		{"http/1.1 client close", httpReq(1, 1, true), httpResp(false), false},
		{"http/1.1 server close (Connection: close or close-delimited)", httpReq(1, 1, false), httpResp(true), false},
		{"http/1.0 default close", httpReq(1, 0, false), httpResp(false), false},
		{"http/0.9 default close", httpReq(0, 9, false), httpResp(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canKeepAlive(tc.req, tc.resp); got != tc.want {
				t.Errorf("canKeepAlive = %v, want %v", got, tc.want)
			}
		})
	}
}
