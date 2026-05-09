package mitm

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/metacubex/http"
)

func TestIsHTTPTraffic(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"GET with space", []byte("GET / H"), true},
		{"POST with space", []byte("POST /"), true},
		// Methods whose length matches the peek window leave no trailing
		// space — must still be recognised as HTTP.
		{"OPTIONS no space", []byte("OPTIONS"), true},
		{"CONNECT no space", []byte("CONNECT"), true},
		{"unknown no space", []byte("HELLOXX"), false},
		{"unknown with space", []byte("HELLO /"), false},
		{"TLS handshake byte", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHTTPTraffic(tc.buf); got != tc.want {
				t.Errorf("isHTTPTraffic(%q) = %v, want %v", tc.buf, got, tc.want)
			}
		})
	}
}

func TestReadDecompressedBodyCap(t *testing.T) {
	// Plain body just over the cap is rejected.
	big := bytes.Repeat([]byte("a"), 100)
	res := &http.Response{
		Body:   io.NopCloser(bytes.NewReader(big)),
		Header: http.Header{},
	}
	if _, err := ReadDecompressedBody(res, 50); err != ErrBodyTooLarge {
		t.Fatalf("expected ErrBodyTooLarge, got %v", err)
	}

	// Plain body under the cap reads cleanly.
	res = &http.Response{
		Body:   io.NopCloser(strings.NewReader("hello")),
		Header: http.Header{},
	}
	got, err := ReadDecompressedBody(res, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", got)
	}

	// Gzip-encoded body whose decoded payload exceeds the cap is rejected
	// even though the compressed bytes fit.
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	res = &http.Response{
		Body:   io.NopCloser(&compressed),
		Header: http.Header{"Content-Encoding": []string{"gzip"}},
	}
	if _, err := ReadDecompressedBody(res, 1024); err != ErrBodyTooLarge {
		t.Fatalf("expected ErrBodyTooLarge for oversized gzip, got %v", err)
	}
}
