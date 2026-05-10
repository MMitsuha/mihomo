package rewrite

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/mitm"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var _ mitm.Handler = (*Handler)(nil)

type Handler struct {
	rules C.RewriteRule
}

func NewHandler(rules C.RewriteRule) *Handler {
	return &Handler{rules: rules}
}

func (h *Handler) HandleRequest(session *mitm.Session) (*http.Request, *http.Response) {
	request := session.Request()
	rule, sub, found := h.matchRewriteRule(request.URL.String(), true)
	if !found {
		return nil, nil
	}

	log.Infoln("[MITM] %s <- request %s", rule.RuleType().String(), request.URL.String())

	var response *http.Response
	switch rule.RuleType() {
	case C.MitmReject:
		response = session.NewResponse(http.StatusNotFound, nil)
		response.Header.Set("Content-Type", "text/html; charset=utf-8")
	case C.MitmReject200:
		response = session.NewResponse(http.StatusOK, nil)
		response.Header.Set("Content-Type", "text/html; charset=utf-8")
	case C.MitmRejectImg:
		response = session.NewResponse(http.StatusOK, OnePixelPNG.Body())
		response.Header.Set("Content-Type", "image/png")
		response.ContentLength = OnePixelPNG.ContentLength()
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	case C.MitmRejectDict:
		response = session.NewResponse(http.StatusOK, EmptyDict.Body())
		response.Header.Set("Content-Type", "application/json; charset=utf-8")
		response.ContentLength = EmptyDict.ContentLength()
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	case C.MitmRejectArray:
		response = session.NewResponse(http.StatusOK, EmptyArray.Body())
		response.Header.Set("Content-Type", "application/json; charset=utf-8")
		response.ContentLength = EmptyArray.ContentLength()
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	case C.Mitm302:
		response = session.NewResponse(http.StatusFound, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.Mitm307:
		response = session.NewResponse(http.StatusTemporaryRedirect, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.MitmRequestHeader:
		if rewriteHeader(request.Header, rule) {
			return request, nil
		}
		return nil, nil
	case C.MitmRequestBody:
		if rewriteRequestBody(request, rule) {
			return request, nil
		}
		return nil, nil
	default:
		return nil, nil
	}

	if response != nil {
		response.Close = true
	}
	return request, response
}

func (h *Handler) HandleResponse(session *mitm.Session) *http.Response {
	request := session.Request()
	response := session.Response()
	rule, _, found := h.matchRewriteRule(request.URL.String(), false)
	if !found || rule.RuleRegx() == nil {
		return nil
	}

	log.Infoln("[MITM] %s <- response %s", rule.RuleType().String(), request.URL.String())

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		if rewriteHeader(response.Header, rule) {
			if response.ContentLength >= 0 {
				response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
			} else {
				response.Header.Del("Content-Length")
			}
			return response
		}
	case C.MitmResponseBody:
		if rewriteResponseBody(response, rule) {
			return response
		}
	}

	return nil
}

func (h *Handler) HandleError(*mitm.Session, error) {}

func (h *Handler) matchRewriteRule(url string, isRequest bool) (rr C.Rewrite, sub []string, found bool) {
	if h == nil || h.rules == nil {
		return nil, nil, false
	}

	if isRequest {
		found = h.rules.SearchInRequest(func(r C.Rewrite) bool {
			match, err := r.URLRegx().FindStringMatch(url)
			if err != nil || match == nil {
				return false
			}

			rr = r
			for _, fg := range match.Groups() {
				sub = append(sub, fg.String())
			}
			return true
		})
		return
	}

	found = h.rules.SearchInResponse(func(r C.Rewrite) bool {
		matched, err := r.URLRegx().MatchString(url)
		if err != nil || !matched {
			return false
		}
		rr = r
		return true
	})
	return
}

func rewriteHeader(header http.Header, rule C.Rewrite) bool {
	if len(header) == 0 {
		return false
	}

	rawHeader := &bytes.Buffer{}
	if err := header.Write(rawHeader); err != nil {
		return false
	}

	newRawHeader := rule.ReplaceSubPayload(rawHeader.String())
	tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
	newHeader, err := tb.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	for key := range header {
		header.Del(key)
	}
	for key, value := range http.Header(newHeader) {
		header[key] = value
	}
	return true
}

func rewriteRequestBody(request *http.Request, rule C.Rewrite) bool {
	if !CanRewriteBody(request.ContentLength, request.Header.Get("Content-Type")) {
		return false
	}

	buf := make([]byte, request.ContentLength)
	if _, err := io.ReadFull(request.Body, buf); err != nil {
		return false
	}
	_ = request.Body.Close()

	newBody := rule.ReplaceSubPayload(string(buf))
	request.Body = io.NopCloser(strings.NewReader(newBody))
	request.ContentLength = int64(len(newBody))
	request.Header.Set("Content-Length", strconv.FormatInt(request.ContentLength, 10))
	return true
}

func rewriteResponseBody(response *http.Response, rule C.Rewrite) bool {
	if !CanRewriteResponseBody(response.ContentLength, response.Header.Get("Content-Type")) {
		return false
	}

	body, err := mitm.ReadDecompressedBody(response)
	_ = response.Body.Close()
	if err != nil {
		return false
	}

	modifiedBody := []byte(rule.ReplaceSubPayload(string(body)))
	response.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	response.Header.Del("Content-Encoding")
	response.ContentLength = int64(len(modifiedBody))
	response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	return true
}
