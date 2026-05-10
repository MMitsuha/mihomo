package rewrite

import (
	"strings"
	"unicode/utf8"

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
	groups := make([]string, len(matches))
	copy(groups, matches)
	return expandBackrefs(r.rulePayload, groups)
}

// expandBackrefs walks payload once and substitutes $N (1- or 2-digit) with
// groups[N], with $$ as a literal $. Done positionally so capture-group content
// containing literal $N tokens is preserved verbatim — a sequential
// strings.Replace would re-substitute that content into the next pass.
//
// $0 is the full match (mirrors regexp's $0). Out-of-range indices expand to
// the empty string. A trailing $ or $X (X non-digit, non-$) is emitted
// literally.
func expandBackrefs(payload string, groups []string) string {
	var b strings.Builder
	b.Grow(len(payload))
	for i := 0; i < len(payload); {
		c := payload[i]
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(payload) {
			b.WriteByte('$')
			i++
			continue
		}
		next := payload[i+1]
		if next == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if next < '0' || next > '9' {
			b.WriteByte('$')
			i++
			continue
		}
		// Greedy 2-digit index ($10..$99) when in range, else 1-digit.
		end := i + 2
		idx := int(next - '0')
		if end < len(payload) && payload[end] >= '0' && payload[end] <= '9' {
			candidate := idx*10 + int(payload[end]-'0')
			if candidate < len(groups) {
				idx = candidate
				end++
			}
		}
		if idx >= 0 && idx < len(groups) {
			b.WriteString(groups[idx])
		}
		i = end
	}
	return b.String()
}

// ReplaceSubPayload applies the body/header pattern substitution. It iterates
// every match against ruleRegx and replaces it with rulePayload, after
// $1..$N back-reference expansion. Output is built positionally from match
// offsets so a replacement that contains the matched text can't be re-matched
// by later iterations (e.g. old `foo`, new `foo-bar`, input `foo foo`).
//
// Bodies that contain bytes which aren't valid UTF-8 are returned unchanged:
// regexp2 operates on runes, so the []rune round-trip would replace those
// bytes with U+FFFD and silently corrupt binary-leaning text payloads (Latin-1
// HTML, form-encoded blobs, etc.) that slip past the content-type allowlist.
func (r *Rule) ReplaceSubPayload(input string) string {
	if r.ruleRegx == nil {
		return input
	}
	if !utf8.ValidString(input) {
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
		groupStrings := make([]string, len(groups))
		for i, g := range groups {
			groupStrings[i] = g.String()
		}
		b.WriteString(expandBackrefs(r.rulePayload, groupStrings))
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
