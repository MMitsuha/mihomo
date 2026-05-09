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
