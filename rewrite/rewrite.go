package rewrite

import (
	"strconv"
	"strings"

	C "github.com/metacubex/mihomo/constant"

	regexp "github.com/dlclark/regexp2"
	"github.com/gofrs/uuid/v5"
)

// Rule is a single MITM rewrite directive.
type Rule struct {
	id          string
	urlRegx     *regexp.Regexp
	ruleType    C.RewriteType
	ruleRegx    *regexp.Regexp
	rulePayload string
}

func (r *Rule) ID() string                  { return r.id }
func (r *Rule) URLRegx() *regexp.Regexp     { return r.urlRegx }
func (r *Rule) RuleType() C.RewriteType     { return r.ruleType }
func (r *Rule) RuleRegx() *regexp.Regexp    { return r.ruleRegx }
func (r *Rule) RulePayload() string         { return r.rulePayload }

// ReplaceURLPayload substitutes $1..$N capture groups from a URL match.
func (r *Rule) ReplaceURLPayload(matches []string) string {
	out := r.rulePayload
	for i := 1; i < len(matches); i++ {
		out = strings.ReplaceAll(out, "$"+strconv.Itoa(i), matches[i])
	}
	return out
}

// ReplaceSubPayload applies the body/header pattern substitution. It iterates
// every match against ruleRegx and replaces it with rulePayload, after
// $1..$N back-reference expansion.
func (r *Rule) ReplaceSubPayload(input string) string {
	if r.ruleRegx == nil {
		return input
	}

	match, err := r.ruleRegx.FindStringMatch(input)
	for err == nil && match != nil {
		groups := match.Groups()
		payload := r.rulePayload
		for i := 1; i < len(groups); i++ {
			payload = strings.Replace(payload, "$"+strconv.Itoa(i), groups[i].String(), 1)
		}
		input = strings.Replace(input, match.String(), payload, 1)
		match, err = r.ruleRegx.FindNextMatch(match)
	}
	return input
}

// NewRule constructs a rewrite rule.
func NewRule(urlRegx *regexp.Regexp, ruleType C.RewriteType, ruleRegx *regexp.Regexp, payload string) *Rule {
	id, _ := uuid.NewV4()
	return &Rule{
		id:          id.String(),
		urlRegx:     urlRegx,
		ruleType:    ruleType,
		ruleRegx:    ruleRegx,
		rulePayload: payload,
	}
}

var _ C.Rewrite = (*Rule)(nil)
