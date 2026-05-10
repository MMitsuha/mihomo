package rewrite

import (
	"strconv"
	"strings"

	regexp "github.com/dlclark/regexp2"
	"github.com/gofrs/uuid/v5"

	C "github.com/metacubex/mihomo/constant"
)

type RawMitmRule struct {
	Url    string        `yaml:"url" json:"url"`
	Action C.RewriteType `yaml:"action" json:"action"`
	Old    *string       `yaml:"old" json:"old"`
	New    string        `yaml:"new" json:"new"`
}

type RewriteRule struct {
	id          string
	urlRegx     *regexp.Regexp
	ruleType    C.RewriteType
	ruleRegx    *regexp.Regexp
	rulePayload string
}

func (r *RewriteRule) ID() string {
	return r.id
}

func (r *RewriteRule) URLRegx() *regexp.Regexp {
	return r.urlRegx
}

func (r *RewriteRule) RuleType() C.RewriteType {
	return r.ruleType
}

func (r *RewriteRule) RuleRegx() *regexp.Regexp {
	return r.ruleRegx
}

func (r *RewriteRule) RulePayload() string {
	return r.rulePayload
}

func (r *RewriteRule) ReplaceURLPayload(matchSub []string) string {
	url := r.rulePayload
	for i := 1; i < len(matchSub); i++ {
		url = strings.ReplaceAll(url, "$"+strconv.Itoa(i), matchSub[i])
	}
	return url
}

func (r *RewriteRule) ReplaceSubPayload(oldData string) string {
	if r.ruleRegx == nil {
		return oldData
	}

	payload := r.rulePayload
	sub, err := r.ruleRegx.FindStringMatch(oldData)
	for err == nil && sub != nil {
		groups := make([]string, 0, len(sub.Groups()))
		for _, fg := range sub.Groups() {
			groups = append(groups, fg.String())
		}

		replacement := payload
		for i := 1; i < len(groups); i++ {
			replacement = strings.ReplaceAll(replacement, "$"+strconv.Itoa(i), groups[i])
		}

		oldData = strings.Replace(oldData, groups[0], replacement, 1)
		sub, err = r.ruleRegx.FindNextMatch(sub)
	}
	return oldData
}

func NewRewriteRule(urlRegx *regexp.Regexp, ruleType C.RewriteType, ruleRegx *regexp.Regexp, rulePayload string) *RewriteRule {
	id, _ := uuid.NewV4()
	return &RewriteRule{
		id:          id.String(),
		urlRegx:     urlRegx,
		ruleType:    ruleType,
		ruleRegx:    ruleRegx,
		rulePayload: rulePayload,
	}
}

var _ C.Rewrite = (*RewriteRule)(nil)
