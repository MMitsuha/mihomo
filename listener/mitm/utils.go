package mitm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/http"
)

var (
	ErrInvalidResponse = errors.New("invalid response")
	ErrInvalidURL      = errors.New("invalid URL")
)

func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
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

func NewErrorResponse(req *http.Request, err error) *http.Response {
	res := NewResponse(http.StatusBadGateway, nil, req)
	res.Close = true

	date := res.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	res.Header.Add("Warning", fmt.Sprintf(`199 "mihomo" %q %q`, err.Error(), date))
	return res
}

func ReadDecompressedBody(res *http.Response) ([]byte, error) {
	rBody := res.Body
	if strings.EqualFold(res.Header.Get("Content-Encoding"), "gzip") {
		gzReader, err := gzip.NewReader(rBody)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		rBody = gzReader
	}
	return io.ReadAll(rBody)
}

func removeProxyHeaders(header http.Header) {
	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
}

func removeHopByHopHeaders(header http.Header) {
	removeProxyHeaders(header)

	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if connections == "" {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

func removeExtraHTTPHostPort(req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	if pHost, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		host = pHost
		if ip, err := netip.ParseAddr(pHost); err == nil && ip.Is6() {
			host = "[" + host + "]"
		}
	}

	req.Host = host
	req.URL.Host = host
}

func isWebsocketRequest(req *http.Request) bool {
	for _, header := range req.Header["Connection"] {
		for _, elm := range strings.Split(header, ",") {
			if strings.EqualFold(strings.TrimSpace(elm), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
				return true
			}
		}
	}
	return false
}

func isHTTPTraffic(buf []byte) bool {
	method, _, _ := strings.Cut(string(buf), " ")
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return true
	default:
		return false
	}
}
