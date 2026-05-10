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

	// hostMatcher is derived from the host portion of urlRegx. It's used by
	// the MITM dispatcher to decide whether to bother terminating TLS — if
	// no rule's hostMatcher matches the SNI, the connection is passed
	// through verbatim. nil means "could match any host" (extraction failed).
	hostMatcher *regexp.Regexp
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
// $1..$N back-reference expansion. Output is built positionally from match
// offsets so a replacement that contains the matched text can't be re-matched
// by later iterations (e.g. old `foo`, new `foo-bar`, input `foo foo`).
func (r *Rule) ReplaceSubPayload(input string) string {
	if r.ruleRegx == nil {
		return input
	}

	// regexp2 reports match offsets in runes, not bytes. Slice the rune view
	// of input to honour those offsets exactly.
	runes := []rune(input)
	var b strings.Builder
	b.Grow(len(input))

	pos := 0
	match, err := r.ruleRegx.FindStringMatch(input)
	for err == nil && match != nil {
		// Zero-length matches consume nothing; treating them as substitution
		// sites would insert the payload at every empty position (e.g. `.*`
		// produces one full match plus an empty match at EOF, doubling the
		// payload). FindNextMatch still advances past zero-width hits, so
		// skipping the body here is safe.
		if match.Length == 0 {
			match, err = r.ruleRegx.FindNextMatch(match)
			continue
		}
		if match.Index > pos {
			b.WriteString(string(runes[pos:match.Index]))
		}
		groups := match.Groups()
		payload := r.rulePayload
		for i := 1; i < len(groups); i++ {
			payload = strings.Replace(payload, "$"+strconv.Itoa(i), groups[i].String(), 1)
		}
		b.WriteString(payload)
		pos = match.Index + match.Length
		match, err = r.ruleRegx.FindNextMatch(match)
	}
	if pos < len(runes) {
		b.WriteString(string(runes[pos:]))
	}
	return b.String()
}

// NewRule constructs a rewrite rule.
func NewRule(urlRegx *regexp.Regexp, ruleType C.RewriteType, ruleRegx *regexp.Regexp, payload string, hostMatcher *regexp.Regexp) *Rule {
	id, _ := uuid.NewV4()
	return &Rule{
		id:          id.String(),
		urlRegx:     urlRegx,
		ruleType:    ruleType,
		ruleRegx:    ruleRegx,
		rulePayload: payload,
		hostMatcher: hostMatcher,
	}
}

// MatchesHost reports whether this rule could match a connection to the given
// host (SNI for HTTPS, Host header for HTTP). nil hostMatcher means the rule's
// URL regex didn't have a clean host portion — be permissive and return true.
func (r *Rule) MatchesHost(host string) bool {
	if r.hostMatcher == nil {
		return true
	}
	ok, _ := r.hostMatcher.MatchString(host)
	return ok
}

var _ C.Rewrite = (*Rule)(nil)
