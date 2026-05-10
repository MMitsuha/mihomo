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
	url := req.URL.String()

	// If a response-body rule will want to rewrite the reply, constrain
	// Accept-Encoding to gzip so mitm.ReadDecompressedBody can decode it.
	// We do not touch other URLs — leaving br/zstd alone preserves origin
	// behaviour and matches the README's passthrough guarantee.
	if req.Header.Get("Accept-Encoding") != "" {
		if respRule, _, ok := matchRule(url, false); ok && respRule.RuleType() == C.MitmResponseBody {
			req.Header.Set("Accept-Encoding", "gzip")
		}
	}

	rule, sub, found := matchRule(url, true)
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
		// Go's parser lifts the Host: line into req.Host and removes it from
		// req.Header — so a user rule like `old: 'Host: example\.com'`
		// against the raw header set wouldn't match anything. Splice Host
		// back in for the regex to see, then strip it out again afterwards
		// (req.Host is what http.Request.Write actually serialises).
		hdrForRewrite := req.Header.Clone()
		if hdrForRewrite == nil {
			hdrForRewrite = http.Header{}
		}
		if req.Host != "" && hdrForRewrite.Get("Host") == "" {
			hdrForRewrite.Set("Host", req.Host)
		}
		newHdr, ok := replaceHeader(hdrForRewrite, rule)
		if !ok {
			return nil, nil
		}
		if h := newHdr.Get("Host"); h != "" {
			req.Host = h
			newHdr.Del("Host")
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
		// Only stamp Content-Length back if the wire form actually had one.
		// For chunked / close-delimited responses ContentLength is -1, and
		// emitting `Content-Length: -1` would be a header rewrite of its own.
		// (metacubex/http drops the header at write time anyway, but we
		// still don't want it leaking via session inspection.)
		if resp.ContentLength >= 0 {
			resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		} else {
			resp.Header.Del("Content-Length")
		}
		return resp
	case C.MitmResponseBody:
		// HEAD responses carry headers (and a possibly non-zero Content-Length)
		// but no body. Rewriting would zero out the advertised length and
		// strip Content-Encoding from the metadata, which is misleading.
		if req.Method == http.MethodHead {
			return nil
		}
		if !CanRewriteResponseBody(resp.ContentLength, resp.Header.Get("Content-Type")) {
			return nil
		}
		// Encoding we can't decode safely — leave the response alone rather
		// than strip Content-Encoding and ship raw compressed bytes as if
		// they were plaintext.
		if !mitm.IsRewritableEncoding(resp.Header.Get("Content-Encoding")) {
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
// block, then re-parses it. Returns ok=false if there are no headers, if
// re-parsing fails, or if the rewrite collapsed the header set to empty —
// otherwise an over-eager rule (`old: '.*'`, `new: ''`) would wipe the
// entire request/response.
func replaceHeader(h http.Header, rule C.Rewrite) (http.Header, bool) {
	if len(h) == 0 {
		return nil, false
	}

	var raw bytes.Buffer
	if err := h.Write(&raw); err != nil {
		return nil, false
	}
	updated := rule.ReplaceSubPayload(raw.String())
	if updated == raw.String() {
		// Regex didn't match — surface a no-op so the caller leaves req/resp
		// untouched (otherwise we re-parse and clobber header ordering /
		// canonicalisation for nothing).
		return nil, false
	}

	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(updated)))
	parsed, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	if len(parsed) == 0 {
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
