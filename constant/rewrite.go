package constant

import (
	"encoding/json"
	"errors"
	"strings"

	regexp "github.com/dlclark/regexp2"
)

var RewriteTypeMapping = map[string]RewriteType{
	MitmReject.String():         MitmReject,
	MitmReject200.String():      MitmReject200,
	MitmRejectImg.String():      MitmRejectImg,
	MitmRejectDict.String():     MitmRejectDict,
	MitmRejectArray.String():    MitmRejectArray,
	Mitm302.String():            Mitm302,
	Mitm307.String():            Mitm307,
	MitmRequestHeader.String():  MitmRequestHeader,
	MitmRequestBody.String():    MitmRequestBody,
	MitmResponseHeader.String(): MitmResponseHeader,
	MitmResponseBody.String():   MitmResponseBody,
}

const (
	MitmReject RewriteType = iota
	MitmReject200
	MitmRejectImg
	MitmRejectDict
	MitmRejectArray

	Mitm302
	Mitm307

	MitmRequestHeader
	MitmRequestBody

	MitmResponseHeader
	MitmResponseBody
)

type RewriteType int

func (e *RewriteType) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := RewriteTypeMapping[tp]
	if !exist {
		return errors.New("invalid MITM action")
	}
	*e = mode
	return nil
}

func (e RewriteType) MarshalYAML() (any, error) {
	return e.String(), nil
}

func (e *RewriteType) UnmarshalJSON(data []byte) error {
	var tp string
	if err := json.Unmarshal(data, &tp); err != nil {
		return err
	}
	mode, exist := RewriteTypeMapping[tp]
	if !exist {
		return errors.New("invalid MITM action")
	}
	*e = mode
	return nil
}

func (e RewriteType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (rt RewriteType) String() string {
	switch rt {
	case MitmReject:
		return "reject"
	case MitmReject200:
		return "reject-200"
	case MitmRejectImg:
		return "reject-img"
	case MitmRejectDict:
		return "reject-dict"
	case MitmRejectArray:
		return "reject-array"
	case Mitm302:
		return "302"
	case Mitm307:
		return "307"
	case MitmRequestHeader:
		return "request-header"
	case MitmRequestBody:
		return "request-body"
	case MitmResponseHeader:
		return "response-header"
	case MitmResponseBody:
		return "response-body"
	default:
		return "Unknown"
	}
}

type Rewrite interface {
	ID() string
	URLRegx() *regexp.Regexp
	RuleType() RewriteType
	RuleRegx() *regexp.Regexp
	RulePayload() string
	ReplaceURLPayload([]string) string
	ReplaceSubPayload(string) string
}

type RewriteRule interface {
	SearchInRequest(func(Rewrite) bool) bool
	SearchInResponse(func(Rewrite) bool) bool
}

var MitmEncryptedSNIPolicyMapping = map[string]MitmEncryptedSNIPolicy{
	MitmEncryptedSNISkip.String():   MitmEncryptedSNISkip,
	MitmEncryptedSNIMitm.String():   MitmEncryptedSNIMitm,
	MitmEncryptedSNIReject.String(): MitmEncryptedSNIReject,
}

const (
	MitmEncryptedSNISkip MitmEncryptedSNIPolicy = iota
	MitmEncryptedSNIMitm
	MitmEncryptedSNIReject
)

type MitmEncryptedSNIPolicy int

func (p *MitmEncryptedSNIPolicy) UnmarshalYAML(unmarshal func(any) error) error {
	var policy string
	if err := unmarshal(&policy); err != nil {
		return err
	}
	mode, exist := MitmEncryptedSNIPolicyMapping[policy]
	if !exist {
		return errors.New("invalid MITM encrypted-sni-policy")
	}
	*p = mode
	return nil
}

func (p MitmEncryptedSNIPolicy) MarshalYAML() (any, error) {
	return p.String(), nil
}

func (p *MitmEncryptedSNIPolicy) UnmarshalJSON(data []byte) error {
	var policy string
	if err := json.Unmarshal(data, &policy); err != nil {
		return err
	}
	mode, exist := MitmEncryptedSNIPolicyMapping[policy]
	if !exist {
		return errors.New("invalid MITM encrypted-sni-policy")
	}
	*p = mode
	return nil
}

func (p MitmEncryptedSNIPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p MitmEncryptedSNIPolicy) String() string {
	switch p {
	case MitmEncryptedSNISkip:
		return "skip"
	case MitmEncryptedSNIMitm:
		return "mitm"
	case MitmEncryptedSNIReject:
		return "reject"
	default:
		return "Unknown"
	}
}

type MitmConfig struct {
	Enable             bool                   `json:"enable"`
	Domain             []string               `json:"domain,omitempty"`
	Ports              []uint16               `json:"ports"`
	Rules              RewriteRule            `json:"-"`
	DomainMatchers     []DomainMatcher        `json:"-"`
	EncryptedSNIPolicy MitmEncryptedSNIPolicy `json:"encrypted-sni-policy"`
}

func (m *MitmConfig) ShouldHandle(port uint16) bool {
	if m == nil || !m.Enable {
		return false
	}
	for _, candidate := range m.Ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func (m *MitmConfig) HasDomainFilter() bool {
	return m != nil && len(m.DomainMatchers) > 0
}

func (m *MitmConfig) ShouldHandleDomain(host string) bool {
	if m == nil {
		return false
	}
	if !m.HasDomainFilter() {
		return true
	}

	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	if host == "" {
		return false
	}

	for _, matcher := range m.DomainMatchers {
		if matcher.MatchDomain(host) {
			return true
		}
	}
	return false
}
