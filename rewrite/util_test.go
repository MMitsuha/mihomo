package rewrite

import "testing"

func TestCanRewriteRequestBody(t *testing.T) {
	cases := []struct {
		name          string
		contentLength int64
		contentType   string
		want          bool
	}{
		{"unknown length", -1, "application/json", false},
		{"zero length", 0, "application/json", false},
		{"oversize", MaxRewriteBodySize + 1, "application/json", false},
		{"text under cap", 10, "text/plain", true},
		{"json under cap", 10, "application/json; charset=utf-8", true},
		{"binary disallowed", 10, "application/octet-stream", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanRewriteRequestBody(tc.contentLength, tc.contentType); got != tc.want {
				t.Errorf("CanRewriteRequestBody = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCanRewriteResponseBody locks in the chunked-skip behaviour. Earlier
// versions accepted ContentLength == -1, which forced large chunked replies
// through ReadDecompressedBody and turned ErrBodyTooLarge into a synthetic
// 502 instead of letting the original response pass through.
func TestCanRewriteResponseBody(t *testing.T) {
	cases := []struct {
		name          string
		contentLength int64
		contentType   string
		want          bool
	}{
		{"chunked rejected", -1, "application/json", false},
		{"zero rejected", 0, "application/json", false},
		{"oversize rejected", MaxRewriteBodySize + 1, "application/json", false},
		{"json under cap accepted", 10, "application/json", true},
		{"text under cap accepted", 10, "text/html", true},
		{"binary rejected", 10, "image/png", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanRewriteResponseBody(tc.contentLength, tc.contentType); got != tc.want {
				t.Errorf("CanRewriteResponseBody = %v, want %v", got, tc.want)
			}
		})
	}
}
