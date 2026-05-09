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

// Handler is the mitm.Handler that applies the active rewrite rule set.
type Handler struct{}

var _ mitm.Handler = (*Handler)(nil)

// HandleRequest applies request-phase rules. Returns either:
//   - a modified request to forward, or
//   - a synthetic response to short-circuit the exchange.
func (Handler) HandleRequest(session *mitm.Session) (*http.Request, *http.Response) {
	req := session.Request()
	rule, sub, found := matchRule(req.URL.String(), true)
	if !found {
		return nil, nil
	}

	log.Infoln("[MITM] %s <- request %s", rule.RuleType().String(), req.URL.String())

	switch rule.RuleType() {
	case C.MitmReject:
		return nil, htmlResponse(session, http.StatusNotFound)
	case C.MitmReject200:
		return nil, htmlResponse(session, http.StatusOK)
	case C.MitmRejectImg:
		resp := session.NewResponse(http.StatusOK, OnePixelPNG.Body())
		resp.Header.Set("Content-Type", "image/png")
		resp.ContentLength = OnePixelPNG.ContentLength()
		resp.Close = true
		return nil, resp
	case C.MitmRejectDict:
		resp := session.NewResponse(http.StatusOK, EmptyDict.Body())
		resp.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp.ContentLength = EmptyDict.ContentLength()
		resp.Close = true
		return nil, resp
	case C.MitmRejectArray:
		resp := session.NewResponse(http.StatusOK, EmptyArray.Body())
		resp.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp.ContentLength = EmptyArray.ContentLength()
		resp.Close = true
		return nil, resp
	case C.Mitm302:
		resp := session.NewResponse(http.StatusFound, nil)
		resp.Header.Set("Location", rule.ReplaceURLPayload(sub))
		resp.Close = true
		return nil, resp
	case C.Mitm307:
		resp := session.NewResponse(http.StatusTemporaryRedirect, nil)
		resp.Header.Set("Location", rule.ReplaceURLPayload(sub))
		resp.Close = true
		return nil, resp
	case C.MitmRequestHeader:
		newHdr, ok := replaceHeader(req.Header, rule)
		if !ok {
			return nil, nil
		}
		req.Header = newHdr
		return req, nil
	case C.MitmRequestBody:
		if !CanRewriteRequestBody(req.ContentLength, req.Header.Get("Content-Type")) {
			return nil, nil
		}
		buf := make([]byte, req.ContentLength)
		if _, err := io.ReadFull(req.Body, buf); err != nil {
			// io.ReadFull may have already consumed part of req.Body;
			// forwarding the original request now would send a truncated
			// payload upstream. Fail the request with a synthetic 502
			// instead so the connection state stays consistent.
			return nil, session.NewErrorResponse(err)
		}
		body := rule.ReplaceSubPayload(string(buf))
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		return req, nil
	}
	return nil, nil
}

// HandleResponse applies response-phase rules.
func (Handler) HandleResponse(session *mitm.Session) *http.Response {
	req := session.Request()
	resp := session.Response()

	rule, _, found := matchRule(req.URL.String(), false)
	if !found || rule.RuleRegx() == nil {
		return nil
	}

	log.Infoln("[MITM] %s <- response %s", rule.RuleType().String(), req.URL.String())

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		newHdr, ok := replaceHeader(resp.Header, rule)
		if !ok {
			return nil
		}
		resp.Header = newHdr
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		return resp
	case C.MitmResponseBody:
		if !CanRewriteResponseBody(resp.ContentLength, resp.Header.Get("Content-Type")) {
			return nil
		}
		body, err := mitm.ReadDecompressedBody(resp, MaxRewriteBodySize)
		_ = resp.Body.Close()
		if err != nil {
			// Body has been (partially) consumed and closed; returning
			// the original resp would write Content-Length headers with
			// no payload behind them. Surface a 502 instead so the wire
			// response is well-formed.
			return session.NewErrorResponse(err)
		}
		newBody := []byte(rule.ReplaceSubPayload(string(body)))
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Transfer-Encoding") // we now know the full size
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		return resp
	}
	return nil
}

// HandleAPIRequest leaves API hijacking to the listener default (cert.crt).
func (Handler) HandleAPIRequest(*mitm.Session) bool { return false }

// HandleError logs the error.
func (Handler) HandleError(_ *mitm.Session, err error) {
	if err != nil {
		log.Debugln("[MITM] error: %s", err.Error())
	}
}

func htmlResponse(session *mitm.Session, status int) *http.Response {
	resp := session.NewResponse(status, nil)
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Close = true
	return resp
}

// replaceHeader applies a header-substitution rule on the wire-format header
// block, then re-parses it. Returns ok=false if there are no headers or if
// re-parsing fails.
func replaceHeader(h http.Header, rule C.Rewrite) (http.Header, bool) {
	if len(h) == 0 {
		return nil, false
	}

	var raw bytes.Buffer
	if err := h.Write(&raw); err != nil {
		return nil, false
	}
	updated := rule.ReplaceSubPayload(raw.String())

	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(updated)))
	parsed, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	return http.Header(parsed), true
}

// matchRule searches the active rule set. For request rules it returns the
// captured sub-groups so $N back-references can be expanded; response rules
// don't need them.
func matchRule(url string, request bool) (rule C.Rewrite, sub []string, found bool) {
	rules := Current()
	if request {
		found = rules.SearchInRequest(func(r C.Rewrite) bool {
			match, err := r.URLRegx().FindStringMatch(url)
			if err != nil || match == nil {
				return false
			}
			rule = r
			groups := match.Groups()
			sub = make([]string, len(groups))
			for i, g := range groups {
				sub[i] = g.String()
			}
			return true
		})
	} else {
		found = rules.SearchInResponse(func(r C.Rewrite) bool {
			ok, err := r.URLRegx().MatchString(url)
			if !ok || err != nil {
				return false
			}
			rule = r
			return true
		})
	}
	return
}
