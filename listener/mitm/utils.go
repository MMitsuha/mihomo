package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metacubex/http"

	"github.com/andybalholm/brotli"
)

var (
	ErrInvalidResponse = errors.New("mitm: invalid response")
	ErrInvalidURL      = errors.New("mitm: invalid URL")
)

const (
	readDeadline = 65 * time.Second
	peekDeadline = time.Second

	// sniPeekBufSize is the bufio buffer size for the initial peek on a
	// MITM-targeted connection. The TLS plaintext fragment cap is 2^14
	// bytes plus a 5-byte record header, so 17 KiB comfortably holds any
	// legal ClientHello.
	sniPeekBufSize = 17 * 1024
)

// NewResponse builds a baseline http.Response inheriting the request protocol.
func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = bytes.NewReader(nil)
	}
	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}
	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}
	return res
}

// NewErrorResponse builds a 502 carrying err as a Warning header (RFC 7234).
func NewErrorResponse(req *http.Request, err error) *http.Response {
	res := NewResponse(http.StatusBadGateway, nil, req)
	res.Close = true
	res.Header.Set("Warning", fmt.Sprintf(`199 "mihomo" %q %q`, err.Error(), time.Now().UTC().Format(http.TimeFormat)))
	return res
}

// ErrBodyTooLarge is returned by ReadDecompressedBody when the body exceeds
// the supplied size cap. Callers should treat this as a non-rewritable body.
var ErrBodyTooLarge = errors.New("mitm: body exceeds max rewrite size")

// ErrUnsupportedEncoding is returned by ReadDecompressedBody when
// Content-Encoding names an algorithm we don't implement (zstd, compress,
// chained encodings, ...). The caller MUST NOT consume the body when this
// error is returned — the function returns it before reading any bytes so
// the caller can fall through and forward the response unchanged.
var ErrUnsupportedEncoding = errors.New("mitm: unsupported content-encoding")

// IsRewritableEncoding reports whether the given Content-Encoding header
// value names an algorithm ReadDecompressedBody can decode. It is
// case-insensitive (per RFC 9110 §8.4.1) and rejects multi-encodings
// like `gzip, br` that would require chained decoding. Empty input
// (no encoding) returns true.
func IsRewritableEncoding(contentEncoding string) bool {
	enc := strings.TrimSpace(contentEncoding)
	if enc == "" {
		return true
	}
	if strings.ContainsRune(enc, ',') {
		return false
	}
	switch strings.ToLower(enc) {
	case "identity", "gzip", "x-gzip", "deflate", "br":
		return true
	}
	return false
}

// ReadDecompressedBody reads res.Body, transparently decoding gzip/deflate/br.
// At most max bytes of decoded output are read; anything larger returns
// ErrBodyTooLarge so a chunked / streamed response can't OOM the proxy. The
// caller owns closing res.Body.
//
// Encodings the function can't decode return ErrUnsupportedEncoding without
// touching res.Body, so the caller can leave the response intact for the
// upstream → client copy.
func ReadDecompressedBody(res *http.Response, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, ErrBodyTooLarge
	}

	enc := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	if strings.ContainsRune(enc, ',') {
		return nil, ErrUnsupportedEncoding
	}

	// Cap input bytes too — for non-compressed bodies this directly bounds
	// memory; for compressed bodies it bounds the read but the decoded
	// output is checked separately below.
	src := io.LimitReader(res.Body, max+1)

	var reader io.Reader = src
	switch enc {
	case "", "identity":
		// no-op
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(src)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case "deflate":
		fr := flate.NewReader(src)
		defer fr.Close()
		reader = fr
	case "br":
		reader = brotli.NewReader(src)
	default:
		return nil, ErrUnsupportedEncoding
	}

	data, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, ErrBodyTooLarge
	}
	return data, nil
}

func isWebsocketRequest(req *http.Request) bool {
	for _, h := range req.Header.Values("Connection") {
		for _, p := range splitTrim(h, ",") {
			if equalsIgnoreCase(p, "upgrade") {
				if equalsIgnoreCase(req.Header.Get("Upgrade"), "websocket") {
					return true
				}
			}
		}
	}
	return false
}

func isHTTPTraffic(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	if idx := bytes.IndexByte(buf, ' '); idx > 0 {
		return validMethod(string(buf[:idx]))
	}
	// No space yet — happens when the peek window is exactly the length
	// of a 7-char method like "OPTIONS" or "CONNECT". Accept the buffer
	// itself as a candidate method so the peek-7 fast path still works.
	return validMethod(string(buf))
}

// validMethod checks whether method is a recognised HTTP request method.
// The list mirrors net/http.validMethod.
func validMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE":
		return true
	}
	return false
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			parts = append(parts, trimSpace(s[start:i]))
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, trimSpace(s[start:]))
	return parts
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func equalsIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
