package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseMitmConfig(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
mitm:
  enable: true
  ports: [80, 443, 8443]
  rules:
    - url: '^https?://ads\.example\.com/.*'
      action: reject
    - url: '^https?://api\.example\.com/v1/(.*)'
      action: '302'
      new: 'https://api.example.com/v2/$1'
    - url: '^https?://example\.com/.*'
      action: request-header
      old: 'User-Agent: .*'
      new: 'User-Agent: mihomo-mitm'
    - url: '^https?://example\.com/score'
      action: response-body
      old: '"score":\d+'
      new: '"score":999'
`))
	if err != nil {
		t.Fatal(err)
	}

	mitm, err := parseMitm(raw.Mitm)
	if err != nil {
		t.Fatal(err)
	}
	if mitm == nil || !mitm.Enable {
		t.Fatal("expected MITM to be enabled")
	}
	if !mitm.ShouldHandle(80) || !mitm.ShouldHandle(443) || !mitm.ShouldHandle(8443) {
		t.Fatalf("expected MITM ports to include 80, 443, and 8443: %#v", mitm.Ports)
	}
	if mitm.ShouldHandle(8080) {
		t.Fatal("expected MITM not to handle unconfigured port 8080")
	}

	var found302 bool
	mitm.Rules.SearchInRequest(func(rule C.Rewrite) bool {
		if rule.RuleType() == C.Mitm302 {
			found302 = true
			return true
		}
		return false
	})
	if !found302 {
		t.Fatal("expected 302 rewrite rule to be parsed as a request rule")
	}

	var foundResponseBody bool
	mitm.Rules.SearchInResponse(func(rule C.Rewrite) bool {
		if rule.RuleType() == C.MitmResponseBody {
			foundResponseBody = true
			return true
		}
		return false
	})
	if !foundResponseBody {
		t.Fatal("expected response-body rewrite rule to be parsed as a response rule")
	}
}
