package constant

import (
	"encoding/json"
	"errors"

	regexp "github.com/dlclark/regexp2"
)

// RewriteType is a MITM rewrite action.
type RewriteType int

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

// RewriteTypeMapping maps human-readable action names to RewriteType.
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

func (r RewriteType) String() string {
	switch r {
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
		return "unknown"
	}
}

func (r *RewriteType) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, ok := RewriteTypeMapping[s]
	if !ok {
		return errors.New("invalid MITM action: " + s)
	}
	*r = v
	return nil
}

func (r RewriteType) MarshalYAML() (any, error) {
	return r.String(), nil
}

func (r *RewriteType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, ok := RewriteTypeMapping[s]
	if !ok {
		return errors.New("invalid MITM action: " + s)
	}
	*r = v
	return nil
}

func (r RewriteType) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// Rewrite is a single rewrite rule that targets requests or responses whose
// URL matches URLRegx.
type Rewrite interface {
	ID() string
	URLRegx() *regexp.Regexp
	RuleType() RewriteType
	RuleRegx() *regexp.Regexp
	RulePayload() string
	ReplaceURLPayload([]string) string
	ReplaceSubPayload(string) string
}

// RewriteRule is a collection of Rewrite entries split by request/response phase.
type RewriteRule interface {
	SearchInRequest(func(Rewrite) bool) bool
	SearchInResponse(func(Rewrite) bool) bool
}
