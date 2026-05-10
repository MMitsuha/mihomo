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
	trimmedURL := strings.TrimSpace(raw.URL)
	urlRegx, err := regexp.Compile(trimmedURL, regexp.None)
	if err != nil {
		return nil, err
	}

	hostMatcher := compileHostMatcher(trimmedURL)

	var (
		ruleRegx *regexp.Regexp
		payload  string
	)

	switch raw.Action {
	case C.Mitm302, C.Mitm307:
		payload = raw.New
	case C.MitmRequestHeader, C.MitmRequestBody, C.MitmResponseHeader, C.MitmResponseBody:
		// `\A[\s\S]*\z` matches the entire input exactly once (anchored
		// start + end, [\s\S] consumes newlines). The naive default `.*`
		// also produces a zero-length match at EOF, which the substitution
		// loop would treat as a second hit and append the payload twice.
		old := `\A[\s\S]*\z`
		if raw.Old != nil {
			old = *raw.Old
		}
		ruleRegx, err = regexp.Compile(old, regexp.Singleline)
		if err != nil {
			return nil, err
		}
		payload = raw.New
	}

	return NewRule(urlRegx, raw.Action, ruleRegx, payload, hostMatcher), nil
}

// compileHostMatcher attempts to extract the host portion from a URL regex of
// the form `^https?://<host>/...`. It returns a regex anchored to match a
// full SNI/Host string, or nil if extraction fails (in which case the rule is
// treated as matching every host — the safe default).
func compileHostMatcher(urlPattern string) *regexp.Regexp {
	host := extractHostPattern(urlPattern)
	if host == "" {
		return nil
	}
	r, err := regexp.Compile("^"+host+"$", regexp.IgnoreCase)
	if err != nil {
		return nil
	}
	return r
}

// extractHostPattern pulls the host portion out of a URL regex. It expects
// patterns shaped like `^https?://<host>/...` (or http/https variants) and
// returns the regex string for <host>, or "" if the input doesn't fit.
//
// Common host fragments use regex constructs that contain the same characters
// we'd otherwise treat as host terminators, e.g. `[^/]+`, `(?:foo|bar)`, IPv6
// brackets `\[::1\]`. Track the bracket / paren nesting so those don't cause
// a premature truncation; falling back to "" (which compileHostMatcher
// translates into "permissive — match every host") is far more disruptive
// here, because every targeted port then gets every host's TLS terminated.
func extractHostPattern(urlPattern string) string {
	s := strings.TrimSpace(urlPattern)
	s = strings.TrimPrefix(s, "^")

	matched := false
	for _, p := range []string{"https?://", "https://", "http://"} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			matched = true
			break
		}
	}
	if !matched {
		return ""
	}

	end := len(s)
	classDepth := 0
	groupDepth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++ // skip the escaped char
			continue
		}
		if classDepth > 0 {
			if c == ']' {
				classDepth--
			}
			continue
		}
		switch c {
		case '[':
			classDepth++
			continue
		case '(':
			groupDepth++
			continue
		case ')':
			if groupDepth > 0 {
				groupDepth--
			}
			continue
		}
		if groupDepth > 0 {
			continue
		}
		if c == '/' || c == '?' || c == '$' || c == ':' {
			end = i
			break
		}
	}
	if end == 0 {
		return ""
	}
	return s[:end]
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
