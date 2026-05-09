package rewrite

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"

	regexp "github.com/dlclark/regexp2"
)

// RawRule is the YAML/JSON representation of a single rewrite line.
type RawRule struct {
	URL    string        `yaml:"url" json:"url"`
	Action C.RewriteType `yaml:"action" json:"action"`
	Old    *string       `yaml:"old,omitempty" json:"old,omitempty"`
	New    string        `yaml:"new,omitempty" json:"new,omitempty"`
}

// ParseRule converts a raw rule into a compiled Rule.
func ParseRule(raw RawRule) (C.Rewrite, error) {
	urlRegx, err := regexp.Compile(strings.TrimSpace(raw.URL), regexp.None)
	if err != nil {
		return nil, err
	}

	var (
		ruleRegx *regexp.Regexp
		payload  string
	)

	switch raw.Action {
	case C.Mitm302, C.Mitm307:
		payload = raw.New
	case C.MitmRequestHeader, C.MitmRequestBody, C.MitmResponseHeader, C.MitmResponseBody:
		old := ".*"
		if raw.Old != nil {
			old = *raw.Old
		}
		ruleRegx, err = regexp.Compile(old, regexp.Singleline)
		if err != nil {
			return nil, err
		}
		payload = raw.New
	}

	return NewRule(urlRegx, raw.Action, ruleRegx, payload), nil
}

// ParseRules splits raw rules into request- and response-phase buckets.
func ParseRules(raws []RawRule) (*Rules, error) {
	var (
		req []C.Rewrite
		res []C.Rewrite
	)
	for _, raw := range raws {
		rule, err := ParseRule(raw)
		if err != nil {
			return nil, err
		}
		switch raw.Action {
		case C.MitmResponseHeader, C.MitmResponseBody:
			res = append(res, rule)
		default:
			req = append(req, rule)
		}
	}
	return NewRules(req, res), nil
}
