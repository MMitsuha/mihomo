package rewrite

import (
	"strings"

	regexp "github.com/dlclark/regexp2"

	C "github.com/metacubex/mihomo/constant"
)

func ParseRewrite(line RawMitmRule) (C.Rewrite, error) {
	urlRegx, err := regexp.Compile(strings.TrimSpace(line.Url), regexp.None)
	if err != nil {
		return nil, err
	}

	var (
		ruleRegx    *regexp.Regexp
		rulePayload string
	)

	switch line.Action {
	case C.Mitm302, C.Mitm307:
		rulePayload = line.New
	case C.MitmRequestHeader, C.MitmResponseHeader:
		old := ".*"
		if line.Old != nil {
			old = *line.Old
		}

		ruleRegx, err = regexp.Compile(old, regexp.None)
		if err != nil {
			return nil, err
		}
		rulePayload = line.New
	case C.MitmRequestBody, C.MitmResponseBody:
		old := ".*"
		if line.Old != nil {
			old = *line.Old
		}

		ruleRegx, err = regexp.Compile(old, regexp.Singleline)
		if err != nil {
			return nil, err
		}
		rulePayload = line.New
	}

	return NewRewriteRule(urlRegx, line.Action, ruleRegx, rulePayload), nil
}
