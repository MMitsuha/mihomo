package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseMitmConfig(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
mitm:
  enable: true
  domain:
    - +.example.com
    - +.domain.com
  ports: [80, 443, 8443]
  encrypted-sni-policy: reject
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

	mitm, err := parseMitm(raw.Mitm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mitm == nil || !mitm.Enable {
		t.Fatal("expected MITM to be enabled")
	}
	if !mitm.ShouldHandleDomain("example.com") || !mitm.ShouldHandleDomain("ads.example.com") || !mitm.ShouldHandleDomain("api.domain.com") {
		t.Fatalf("expected MITM domain filter to match configured domains and subdomains: %#v", mitm.Domain)
	}
	if mitm.ShouldHandleDomain("example.org") {
		t.Fatal("expected MITM domain filter not to match unconfigured domain")
	}
	if mitm.EncryptedSNIPolicy != C.MitmEncryptedSNIReject {
		t.Fatalf("expected encrypted-sni-policy reject, got %s", mitm.EncryptedSNIPolicy.String())
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

func TestParseMitmConfigDefaultEncryptedSNIPolicy(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
mitm:
  enable: true
  domain:
    - example.com
  ports: [443]
`))
	if err != nil {
		t.Fatal(err)
	}

	mitm, err := parseMitm(raw.Mitm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mitm.EncryptedSNIPolicy != C.MitmEncryptedSNISkip {
		t.Fatalf("expected default encrypted-sni-policy skip, got %s", mitm.EncryptedSNIPolicy.String())
	}
}

func TestParseMitmDomainMatchesDomainSyntax(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
mitm:
  enable: true
  domain:
    - example.com
    - +.domain.com
  ports: [443]
`))
	if err != nil {
		t.Fatal(err)
	}

	mitm, err := parseMitm(raw.Mitm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !mitm.ShouldHandleDomain("example.com") {
		t.Fatal("expected bare domain to match itself")
	}
	if mitm.ShouldHandleDomain("www.example.com") {
		t.Fatal("expected bare domain not to match subdomains")
	}
	if !mitm.ShouldHandleDomain("domain.com") || !mitm.ShouldHandleDomain("www.domain.com") {
		t.Fatal("expected +.domain.com to match itself and subdomains")
	}
}
