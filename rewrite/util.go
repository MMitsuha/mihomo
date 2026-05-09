package rewrite

import "strings"

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

// CanRewriteBody reports whether a body of the given length and type can be
// safely rewritten as text.
func CanRewriteBody(contentLength int64, contentType string) bool {
	if contentLength <= 0 {
		return false
	}
	for _, p := range allowContentType {
		if strings.HasPrefix(contentType, p) {
			return true
		}
	}
	return false
}
