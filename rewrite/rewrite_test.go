package rewrite

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

func TestRewriteURLPayloadBackReference(t *testing.T) {
	rule, err := ParseRewrite(RawMitmRule{
		Url:    `^https?://api\.example\.com/v1/(.*)`,
		Action: C.Mitm302,
		New:    `https://api.example.com/v2/$1`,
	})
	if err != nil {
		t.Fatal(err)
	}

	match, err := rule.URLRegx().FindStringMatch("https://api.example.com/v1/users/42")
	if err != nil {
		t.Fatal(err)
	}

	var groups []string
	for _, group := range match.Groups() {
		groups = append(groups, group.String())
	}

	got := rule.ReplaceURLPayload(groups)
	want := "https://api.example.com/v2/users/42"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRewriteSubPayloadBackReferences(t *testing.T) {
	old := `name=(\w+),score=(\d+)`
	rule, err := ParseRewrite(RawMitmRule{
		Url:    `^https?://example\.com/score`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `score=$2,name=$1`,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := rule.ReplaceSubPayload("name=alice,score=7;name=bob,score=9")
	want := "score=7,name=alice;score=9,name=bob"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRewriteBodyMultilineRegexKeepsFollowingLines(t *testing.T) {
	old := `(?m)^loc=.*$`
	rule, err := ParseRewrite(RawMitmRule{
		Url:    `^https?://crypto\.cloudflare\.com/cdn-cgi/trace`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `loc=AWA`,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := rule.ReplaceSubPayload("http=http/2\nloc=US\ntls=TLSv1.3\nsni=plaintext")
	want := "http=http/2\nloc=AWA\ntls=TLSv1.3\nsni=plaintext"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestCanRewriteBodyTextLikeContentType(t *testing.T) {
	if !CanRewriteBody(12, "application/json; charset=utf-8") {
		t.Fatal("expected json body to be rewriteable")
	}
	if CanRewriteBody(-1, "application/json") {
		t.Fatal("expected request body with unknown content length to be rejected")
	}
	if !CanRewriteResponseBody(-1, "text/plain") {
		t.Fatal("expected response body with unknown content length to be rewriteable")
	}
	if CanRewriteResponseBody(0, "text/plain") {
		t.Fatal("expected empty response body to be rejected")
	}
	if CanRewriteBody(12, "application/octet-stream") {
		t.Fatal("expected binary content type to be rejected")
	}
}

func TestRewriteHeaderKeepsUnmatchedHeaders(t *testing.T) {
	old := `User-Agent: .*`
	rule, err := ParseRewrite(RawMitmRule{
		Url:    `^https?://example\.com/.*`,
		Action: C.MitmRequestHeader,
		Old:    &old,
		New:    `User-Agent: mihomo-mitm`,
	})
	if err != nil {
		t.Fatal(err)
	}

	header := http.Header{}
	header.Set("User-Agent", "original")
	header.Set("Accept", "application/json")

	if !rewriteHeader(header, rule) {
		t.Fatal("expected header rewrite to apply")
	}
	if got := header.Get("User-Agent"); got != "mihomo-mitm" {
		t.Fatalf("expected rewritten user-agent, got %q", got)
	}
	if got := header.Get("Accept"); got != "application/json" {
		t.Fatalf("expected unmatched Accept header to be preserved, got %q", got)
	}
}
