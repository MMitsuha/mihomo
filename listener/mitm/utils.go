package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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

// ReadDecompressedBody reads res.Body, transparently decoding gzip/deflate/br.
// The caller owns closing res.Body. The returned bytes are the decoded payload.
func ReadDecompressedBody(res *http.Response) ([]byte, error) {
	var reader io.Reader = res.Body

	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		gz, err := gzip.NewReader(res.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case "deflate":
		fr := flate.NewReader(res.Body)
		defer fr.Close()
		reader = fr
	case "br":
		reader = brotli.NewReader(res.Body)
	}

	return io.ReadAll(reader)
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
