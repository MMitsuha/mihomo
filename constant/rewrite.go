package constant

import (
	"encoding/json"
	"errors"

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

type MitmConfig struct {
	Enable bool        `json:"enable"`
	Ports  []uint16    `json:"ports"`
	Rules  RewriteRule `json:"-"`
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
