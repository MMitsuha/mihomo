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
