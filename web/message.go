package web

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/sonic"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"net/url"
)

// message:

// type: 0/1/2/3/4/5
// messageFlow
// version 1 byte + type 1 byte + id 36 byte + waitIntercept 1 byte + content left bytes

// type: 11/12/13/14
// messageEdit
// version 1 byte + type 1 byte + id 36 byte + header len 4 byte + header content bytes + body len 4 byte + [body content bytes]

// type: 21
// messageMeta
// version 1 byte + type 1 byte + content left bytes

var (
	TooShortE     = fmt.Errorf("too short message")
	VersionE      = fmt.Errorf("invalid message version")
	InvalidTypeE  = fmt.Errorf("invalid message type")
	InvalidFlowId = fmt.Errorf("invalid message flow id")
	MessageE      = fmt.Errorf("invalid message format")
)

const messageVersion = 2

type messageType byte

const (
	messageTypeConn         messageType = 0
	messageTypeConnClose    messageType = 5
	messageTypeRequest      messageType = 1
	messageTypeRequestBody  messageType = 2
	messageTypeResponse     messageType = 3
	messageTypeResponseBody messageType = 4

	messageTypeChangeRequest  messageType = 11
	messageTypeChangeResponse messageType = 12
	messageTypeDropRequest    messageType = 13
	messageTypeDropResponse   messageType = 14

	messageTypeChangeBreakPointRules messageType = 21
	messageTypeInterceptor           messageType = 22
	messageTypeInterceptorOff        messageType = 23

	messageTypeChangeRequestV2    messageType = 101
	messageTypeChangeResponseV2   messageType = 102
	MessageTypeChangeHistoryRules messageType = 103

	messageTypePull  messageType = 105
	messageTypeFlows messageType = 106

	messageTypeLogin messageType = 110
)

var allMessageTypes = []messageType{
	messageTypeConn,
	messageTypeConnClose,
	messageTypeRequest,
	messageTypeRequestBody,
	messageTypeResponse,
	messageTypeResponseBody,
	messageTypeChangeRequest,
	messageTypeChangeResponse,
	messageTypeDropRequest,
	messageTypeDropResponse,
	messageTypeChangeBreakPointRules,
	messageTypeInterceptor,
	messageTypeInterceptorOff,
	messageTypeChangeRequestV2,
	messageTypeChangeResponseV2,
	MessageTypeChangeHistoryRules,
	messageTypePull,
	messageTypeFlows,
}

func validMessageType(t byte) bool {
	for _, v := range allMessageTypes {
		if t == byte(v) {
			return true
		}
	}
	return false
}

type message interface {
	bytes() []byte
}

type messageFlow struct {
	mType         messageType
	id            uuid.UUID
	waitIntercept byte
	content       []byte
}

func newMessageFlow(mType messageType, f *proxy.Flow) *messageFlow {
	var content []byte
	var err error = nil

	switch mType {
	case messageTypeConn:
		content, err = sonic.Marshal(f.ConnContext)
	case messageTypeRequest:
		m := make(map[string]interface{})
		m["request"] = f.Request
		m["connId"] = f.ConnContext.Id().String()
		content, err = sonic.Marshal(m)
	case messageTypeRequestBody:
		content = f.Request.Body
	case messageTypeResponse:
		content, err = sonic.Marshal(f.Response)
	case messageTypeResponseBody:
		content, err = f.Response.DecodedBody()
	default:
		panic(errors.New("invalid message type"))

	}

	if err != nil {
		panic(err)
	}

	id := f.Id
	if mType == messageTypeConn {
		id = f.ConnContext.Id()
	}

	return &messageFlow{
		mType:   mType,
		id:      id,
		content: content,
	}
}

func newMessageConnClose(connCtx *proxy.ConnContext) *messageFlow {
	return &messageFlow{
		mType: messageTypeConnClose,
		id:    connCtx.Id(),
	}
}

func (m *messageFlow) bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.WriteByte(byte(messageVersion))
	buf.WriteByte(byte(m.mType))
	buf.WriteString(m.id.String()) // len: 36
	buf.WriteByte(m.waitIntercept)
	buf.Write(m.content)
	return buf.Bytes()
}

type messageEdit struct {
	mType    messageType
	id       uuid.UUID
	request  *proxy.Request
	response *proxy.Response
}

func parseMessageEdit(data []byte) (*messageEdit, error) {
	// 2 + 36
	if len(data) < 38 {
		return nil, TooShortE
	}

	mType := (messageType)(data[1])

	id, err := uuid.FromString(string(data[2:38]))
	if err != nil {
		return nil, InvalidFlowId
	}

	msg := &messageEdit{
		mType: mType,
		id:    id,
	}

	if mType == messageTypeDropRequest || mType == messageTypeDropResponse {
		return msg, nil
	}

	// 2 + 36 + 4 + 4
	if len(data) < 46 {
		return nil, TooShortE
	}

	hl := (int)(binary.BigEndian.Uint32(data[38:42]))
	if 42+hl+4 > len(data) {
		return nil, MessageE
	}
	headerContent := data[42 : 42+hl]

	bl := (int)(binary.BigEndian.Uint32(data[42+hl : 42+hl+4]))
	if 42+hl+4+bl != len(data) {
		return nil, MessageE
	}
	bodyContent := data[42+hl+4:]

	if mType == messageTypeChangeRequest {
		req := new(proxy.Request)
		err := json.Unmarshal(headerContent, req)
		if err != nil {
			return nil, MessageE
		}
		req.Body = bodyContent
		msg.request = req
	} else if mType == messageTypeChangeResponse {
		res := new(proxy.Response)
		err := json.Unmarshal(headerContent, res)
		if err != nil {
			return nil, err
		}
		res.Body = bodyContent
		msg.response = res
	} else {
		return nil, MessageE
	}

	return msg, nil
}

func (m *messageEdit) bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.WriteByte(byte(messageVersion))
	buf.WriteByte(byte(m.mType))
	buf.WriteString(m.id.String()) // len: 36

	if m.mType == messageTypeChangeRequest {
		headerContent, err := json.Marshal(m.request)
		if err != nil {
			panic(err)
		}
		hl := make([]byte, 4)
		binary.BigEndian.PutUint32(hl, (uint32)(len(headerContent)))
		buf.Write(hl)

		bodyContent := m.request.Body
		bl := make([]byte, 4)
		binary.BigEndian.PutUint32(bl, (uint32)(len(bodyContent)))
		buf.Write(bl)
		buf.Write(bodyContent)
	} else if m.mType == messageTypeChangeResponse {
		headerContent, err := json.Marshal(m.response)
		if err != nil {
			panic(err)
		}
		hl := make([]byte, 4)
		binary.BigEndian.PutUint32(hl, (uint32)(len(headerContent)))
		buf.Write(hl)

		bodyContent := m.response.Body
		bl := make([]byte, 4)
		binary.BigEndian.PutUint32(bl, (uint32)(len(bodyContent)))
		buf.Write(bl)
		buf.Write(bodyContent)
	}

	return buf.Bytes()
}

type messageMeta struct {
	mType messageType
	rule  *breakPointRule
}

func parseMessageMeta(data []byte) (*messageMeta, error) {
	content := data[2:]

	rule := &breakPointRule{}
	err := json.Unmarshal(content, rule)
	if err != nil {
		return nil, err
	}

	msg := &messageMeta{
		mType: messageType(data[1]),
		rule:  rule,
	}

	msg.parseRule()
	return msg, nil
}

func (m *messageMeta) parseRule() {
	m.rule.parse()
}

func (m *messageMeta) bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.WriteByte(byte(messageVersion))
	buf.WriteByte(byte(m.mType))

	content, err := json.Marshal(m.rule)
	if err != nil {
		panic(err)
	}
	buf.Write(content)

	return buf.Bytes()
}

func NewMessage(data []byte) *messageEdit {
	// 2 + 36
	if len(data) < 38 {
		return nil
	}

	mType := (messageType)(data[1])

	id, err := uuid.FromString(string(data[2:38]))
	if err != nil {
		return nil
	}

	return &messageEdit{
		mType: mType,
		id:    id,
	}
}

type Pull struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

func (p *Pull) bytes() []byte {
	chunk, _ := sonic.Marshal(p)
	return chunk
}

func ParseHistoryPullInfo(data []byte) *Pull {
	var pull Pull
	sonic.Unmarshal(data, &pull)

	return &pull
}

func ParseResponseMessageEdit2(data []byte) (*messageEdit, error) {
	msg := NewMessage(data)
	if msg == nil {
		return nil, nil
	}

	r := proxy.ResponseEditData{}
	content := data[38:]
	err := json.Unmarshal(content, &r)
	if err != nil {
		log.Errorf("unmarshal request edit fail %v", err)
		return nil, err
	}

	msg.response = &proxy.Response{
		StatusCode: r.StatusCode,
		Body:       auxlib.S2B(r.Body),
		Header:     r.Header,
	}

	return msg, nil

}

func ParseRequestMessageEdit2(data []byte) (*messageEdit, error) {
	msg := NewMessage(data)
	if msg == nil {
		return nil, nil
	}

	r := proxy.RequestEditData{}
	content := data[38:]
	err := json.Unmarshal(content, &r)
	if err != nil {
		log.Errorf("unmarshal request edit fail %v", err)
		return nil, err
	}

	url, err := url.Parse(r.RawURL)
	if err != nil {
		log.Errorf("unmarshal request edit url fail %v", err)
		return nil, err
	}
	msg.request = &proxy.Request{
		Method: r.Method,
		Proto:  r.Proto,
		URL:    url,
		Body:   auxlib.S2B(r.Body),
		Header: r.Header,
	}

	return msg, nil
}

func parseMessage(data []byte) (message, error) {
	if len(data) < 2 {
		return nil, TooShortE
	}

	if data[0] != messageVersion {
		return nil, VersionE
	}

	if !validMessageType(data[1]) {
		return nil, InvalidTypeE
	}

	mType := (messageType)(data[1])

	switch mType {
	case messageTypeChangeRequest, messageTypeChangeResponse, messageTypeDropRequest, messageTypeDropResponse:
		return parseMessageEdit(data)
	case messageTypeChangeBreakPointRules:
		return parseMessageMeta(data)
	case messageTypeInterceptor:
		return &Interceptor{enable: data[2]}, nil

	case messageTypeChangeRequestV2:
		return ParseRequestMessageEdit2(data)
	case messageTypeChangeResponseV2:
		return ParseResponseMessageEdit2(data)
	case MessageTypeChangeHistoryRules:
		return parseMessageMeta(data)

	case messageTypePull:
		return ParseHistoryPullInfo(data), nil

	default:
		log.Warnf("invalid message type %v", mType)
		return nil, MessageE
	}
}
