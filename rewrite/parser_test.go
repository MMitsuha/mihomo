package rewrite

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func ptr[T any](v T) *T { return &v }

func TestParseRules(t *testing.T) {
	old := "abc"
	cases := []struct {
		name    string
		raws    []RawRule
		wantReq int
		wantRes int
	}{
		{
			name:    "empty",
			raws:    nil,
			wantReq: 0,
			wantRes: 0,
		},
		{
			name: "mixed",
			raws: []RawRule{
				{URL: `^https?://ads\.example\.com/.*`, Action: C.MitmReject},
				{URL: `^https?://api\.example\.com/v1/(.*)`, Action: C.Mitm302, New: "https://api.example.com/v2/$1"},
				{URL: `^https?://example\.com/.*`, Action: C.MitmRequestHeader, Old: ptr("User-Agent: .*"), New: "User-Agent: mihomo-mitm"},
				{URL: `^https?://example\.com/.*`, Action: C.MitmResponseBody, Old: &old, New: "xyz"},
			},
			wantReq: 3,
			wantRes: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ParseRules(tc.raws)
			if err != nil {
				t.Fatalf("ParseRules: %v", err)
			}
			if len(rules.request) != tc.wantReq {
				t.Errorf("request rules = %d, want %d", len(rules.request), tc.wantReq)
			}
			if len(rules.response) != tc.wantRes {
				t.Errorf("response rules = %d, want %d", len(rules.response), tc.wantRes)
			}
		})
	}
}

func TestRuleReplaceURL(t *testing.T) {
	raw := RawRule{
		URL:    `^https?://api\.example\.com/v1/(.*)`,
		Action: C.Mitm302,
		New:    "https://api.example.com/v2/$1",
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	got := rule.ReplaceURLPayload([]string{"http://api.example.com/v1/users", "users"})
	want := "https://api.example.com/v2/users"
	if got != want {
		t.Errorf("ReplaceURLPayload = %q, want %q", got, want)
	}
}

func TestExtractHostPattern(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`^https?://example\.com/.*`, `example\.com`},
		{`^https?://api\.foo\.com/v1/(.*)`, `api\.foo\.com`},
		{`^https?://(api|cdn)\.foo\.com/.*`, `(api|cdn)\.foo\.com`},
		{`^https?://example\.com$`, `example\.com`},
		{`^https?://example\.com:8080/.*`, `example\.com`}, // port boundary
		{`/api/.*`, ``},                                    // no scheme — extraction fails
		{`^https?://`, ``},                                 // empty host
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := extractHostPattern(tc.in)
			if got != tc.want {
				t.Errorf("extractHostPattern(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRuleMatchesHost(t *testing.T) {
	r1, _ := ParseRule(RawRule{URL: `^https?://api\.example\.com/v1/(.*)`, Action: C.Mitm302, New: "x"})
	r2, _ := ParseRule(RawRule{URL: `^https?://(api|cdn)\.foo\.com/.*`, Action: C.MitmReject})
	r3, _ := ParseRule(RawRule{URL: `^/no-scheme/.*`, Action: C.MitmReject}) // bad pattern, allow-all

	hostMatcher := func(rule C.Rewrite) func(string) bool {
		hm, _ := rule.(interface{ MatchesHost(string) bool })
		return hm.MatchesHost
	}

	if !hostMatcher(r1)("api.example.com") {
		t.Error("r1 should match api.example.com")
	}
	if hostMatcher(r1)("api.other.com") {
		t.Error("r1 should NOT match api.other.com")
	}
	if !hostMatcher(r2)("api.foo.com") {
		t.Error("r2 should match api.foo.com")
	}
	if !hostMatcher(r2)("cdn.foo.com") {
		t.Error("r2 should match cdn.foo.com")
	}
	if hostMatcher(r2)("www.foo.com") {
		t.Error("r2 should NOT match www.foo.com")
	}
	if !hostMatcher(r3)("anything.example.com") {
		t.Error("r3 with no extractable host should be permissive")
	}
}

func TestRuleReplaceSub(t *testing.T) {
	old := `"score":(\d+)`
	raw := RawRule{
		URL:    `.*`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `"score":999`,
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	got := rule.ReplaceSubPayload(`{"name":"a","score":42,"score":7}`)
	want := `{"name":"a","score":999,"score":999}`
	if got != want {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, want)
	}
}

// TestRuleReplaceSubOverlap covers the case where the replacement contains
// the matched text. Earlier implementations used strings.Replace against the
// already-mutated string and would re-match their own output; with
// `foo` -> `foo-bar` on `foo foo` that produced `foo-bar-bar foo` instead
// of `foo-bar foo-bar`.
func TestRuleReplaceSubOverlap(t *testing.T) {
	old := `foo`
	raw := RawRule{
		URL:    `.*`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `foo-bar`,
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	got := rule.ReplaceSubPayload(`foo foo`)
	want := `foo-bar foo-bar`
	if got != want {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, want)
	}
}

// TestRuleReplaceSubOmittedOld covers the omitted-`old` default. Earlier
// versions defaulted to `.*` (with Singleline), which produced a full match
// plus a zero-length match at EOF and therefore duplicated the payload —
// a body rule new=`x` would rewrite "abc" to "xx" instead of "x".
func TestRuleReplaceSubOmittedOld(t *testing.T) {
	raw := RawRule{
		URL:    `.*`,
		Action: C.MitmRequestBody,
		// Old intentionally omitted to exercise the parser default.
		New: "x",
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	got := rule.ReplaceSubPayload("abc")
	if got != "x" {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, "x")
	}
	got = rule.ReplaceSubPayload("line1\nline2")
	if got != "x" {
		t.Errorf("ReplaceSubPayload (multiline) = %q, want %q", got, "x")
	}
	// Empty input is intentionally not exercised: CanRewriteRequestBody
	// rejects ContentLength <= 0 and replaceHeader bails on empty headers,
	// so the substitution path is never invoked with an empty string.
}

// TestRuleReplaceSubZeroLengthSkip locks in the zero-length-match skip even
// when the user supplies a pattern that matches the empty string at every
// position (e.g. `\d*` against non-digit input).
func TestRuleReplaceSubZeroLengthSkip(t *testing.T) {
	old := `\d*`
	raw := RawRule{
		URL:    `.*`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    "X",
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if got := rule.ReplaceSubPayload("abc"); got != "abc" {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, "abc")
	}
	if got := rule.ReplaceSubPayload("a1b22c"); got != "aXbXc" {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, "aXbXc")
	}
}

// TestRuleReplaceSubMultibyte verifies offset handling when the input contains
// runes wider than one byte. regexp2 reports match offsets in runes, so the
// rewriter must slice on the rune view (not bytes) to land replacements in
// the right place.
func TestRuleReplaceSubMultibyte(t *testing.T) {
	old := `score`
	raw := RawRule{
		URL:    `.*`,
		Action: C.MitmResponseBody,
		Old:    &old,
		New:    `值`,
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	got := rule.ReplaceSubPayload(`café score 你好 score end`)
	want := `café 值 你好 值 end`
	if got != want {
		t.Errorf("ReplaceSubPayload = %q, want %q", got, want)
	}
}

// TestRuleReplaceSubInvalidUTF8 checks that bodies containing bytes which
// aren't valid UTF-8 are returned unchanged. Re-encoding via []rune would
// substitute U+FFFD and corrupt the payload — the rewriter must skip the
// substitution rather than mangle binary content that slipped past the
// content-type allowlist.
func TestRuleReplaceSubInvalidUTF8(t *testing.T) {
	old := `foo`
	raw := RawRule{URL: `.*`, Action: C.MitmResponseBody, Old: &old, New: "bar"}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	// Lone 0xff is invalid UTF-8 — Latin-1 encoded "ÿ", binary blob, etc.
	in := "foo\xffbar"
	if got := rule.ReplaceSubPayload(in); got != in {
		t.Errorf("ReplaceSubPayload = %q, want %q (input unchanged)", got, in)
	}
}

// TestExpandBackrefs covers the placeholder substitution: $$ escape, $10+
// indices, and that capture-group content containing literal $N tokens
// doesn't get re-substituted in subsequent iterations.
func TestExpandBackrefs(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		groups  []string
		want    string
	}{
		{"single", "x=$1", []string{"full", "abc"}, "x=abc"},
		{"two-digit", "$11", []string{"0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}, "k"},
		{"two-digit-out-of-range", "$12", []string{"0", "a"}, "a2"},
		{"escape", "$$1=$1", []string{"full", "v"}, "$1=v"},
		{"trailing-dollar", "x$", []string{"full"}, "x$"},
		{"non-digit-after-dollar", "$x", []string{"full"}, "$x"},
		{"out-of-range", "$5", []string{"full", "a"}, ""},
		// Capture-group content containing $N must NOT be re-substituted.
		{"no-cascade", "$1-$2", []string{"full", "$2", "B"}, "$2-B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandBackrefs(tc.payload, tc.groups); got != tc.want {
				t.Errorf("expandBackrefs(%q, %v) = %q, want %q", tc.payload, tc.groups, got, tc.want)
			}
		})
	}
}

// TestRuleReplaceURLNoCascade locks in single-pass URL substitution: a
// captured value containing $N must not pivot subsequent placeholders.
func TestRuleReplaceURLNoCascade(t *testing.T) {
	raw := RawRule{
		URL:    `^https?://example\.com/(.*)/(.*)`,
		Action: C.Mitm302,
		New:    "https://x/$1/$2",
	}
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	// Group 1 contains literal "$2"; the legacy ReplaceAll-based code would
	// substitute that into the second pass and emit "https://x/end/end".
	got := rule.ReplaceURLPayload([]string{"full", "$2", "end"})
	want := "https://x/$2/end"
	if got != want {
		t.Errorf("ReplaceURLPayload = %q, want %q", got, want)
	}
}

// TestExtractHostPatternCharClass guards against premature termination on
// regex characters that nest a `/`, `?`, or `:` inside a `[...]` or `(...)`.
// Falling back to `""` would mark every rule as host-permissive and trigger
// TLS termination on every host on the configured ports.
func TestExtractHostPatternCharClass(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`^https?://[^/]+\.example\.com/.*`, `[^/]+\.example\.com`},
		{`^https?://(?:api|cdn)\.foo\.com/.*`, `(?:api|cdn)\.foo\.com`},
		{`^https?://[a-z0-9-]+\.example\.com/.*`, `[a-z0-9-]+\.example\.com`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := extractHostPattern(tc.in); got != tc.want {
				t.Errorf("extractHostPattern(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
