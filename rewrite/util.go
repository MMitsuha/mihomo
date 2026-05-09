package rewrite

import "strings"

// MaxRewriteBodySize caps how many bytes a single body rewrite is willing to
// buffer. Bodies larger than this are skipped to avoid unbounded memory use.
const MaxRewriteBodySize = 8 << 20 // 8 MiB

// allowContentType lists Content-Type prefixes whose bodies are safe to rewrite
// as text. Binary types (images, video, octet-stream) are skipped.
var allowContentType = []string{
	"text/",
	"application/xhtml",
	"application/xml",
	"application/atom+xml",
	"application/json",
	"application/x-www-form-urlencoded",
}

// CanRewriteRequestBody reports whether a request body can be rewritten.
// Request bodies must have a known Content-Length; chunked requests are
// rejected because the rewrite engine can't size the buffer up front.
func CanRewriteRequestBody(contentLength int64, contentType string) bool {
	if contentLength <= 0 || contentLength > MaxRewriteBodySize {
		return false
	}
	return contentTypeAllowed(contentType)
}

// CanRewriteResponseBody reports whether a response body can be rewritten.
// Like requests, this requires a known Content-Length within the cap. Chunked
// or close-delimited responses (ContentLength == -1) are skipped: they can
// stream past the cap at any time, and a partial read can't be safely
// re-streamed to the client, so we'd otherwise have to fail the exchange
// with 502 instead of just letting the original response through.
func CanRewriteResponseBody(contentLength int64, contentType string) bool {
	if contentLength <= 0 || contentLength > MaxRewriteBodySize {
		return false
	}
	return contentTypeAllowed(contentType)
}

func contentTypeAllowed(contentType string) bool {
	for _, p := range allowContentType {
		if strings.HasPrefix(contentType, p) {
			return true
		}
	}
	return false
}
