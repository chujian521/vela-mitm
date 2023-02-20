package web

import (
	"bytes"
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"net/http/httputil"
	"regexp"
	"strings"
)

type flowL struct {
	stop context.CancelFunc
	flow *proxy.Flow
	ctx  context.Context
	wait bool
}

func (fl *flowL) String() string                         { return "" }
func (fl *flowL) Type() lua.LValueType                   { return lua.LTObject }
func (fl *flowL) AssertFloat64() (float64, bool)         { return 0, false }
func (fl *flowL) AssertString() (string, bool)           { return "", false }
func (fl *flowL) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (fl *flowL) Peek() lua.LValue                       { return fl }

func (fl *flowL) headerL(key string) lua.LValue {
	header := fl.flow.Request.Header

	return lua.S2L(header.Get(key))
}

func (fl *flowL) argL(name string) lua.LValue {
	query := fl.flow.Request.URL.Query()

	value, ok := query[name]
	if !ok {
		return lua.LNil
	}

	if len(value) == 1 {
		return lua.S2L(value[0])
	}

	tab := lua.CreateTable(len(value), 0)
	for i, v := range value {
		tab.RawSetInt(i, lua.S2L(v))
	}

	return tab
}

func (fl *flowL) waitL(L *lua.LState) int {
	fl.wait = true
	fl.stop()
	return 0
}

func (fl *flowL) passL(L *lua.LState) int {
	fl.wait = false
	fl.stop()
	return 0
}

func (fl *flowL) containL(L *lua.LState) int {
	ret := false
	raw, err := httputil.DumpRequest(fl.flow.Request.Raw(), true)
	if err != nil {
		L.Push(lua.LBool(ret))
		return 1
	}

	L.Callback(func(lv lua.LValue) (stop bool) {
		item := lua.S2B(lv.String())
		ret = bytes.Contains(raw, item)
		return ret
	})

	L.Push(lua.LBool(ret))
	return 1

}

func (fl *flowL) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "wait":
		return lua.NewFunction(fl.waitL)
	case "pass":
		return lua.NewFunction(fl.passL)
	case "have":
		return lua.NewFunction(fl.containL)

	case "host":
		return lua.S2L(fl.flow.Request.URL.Host)
	case "uri":
		return lua.S2L(fl.flow.Request.URL.Path)
	case "request":
		return lua.S2L(fl.flow.Request.URL.RequestURI())
	case "query":
		return lua.S2L(fl.flow.Request.URL.RawQuery)
	case "ua":
		return lua.S2L(fl.flow.Request.Header.Get("user-agent"))
	case "body":
		return lua.B2L(fl.flow.Request.Body)
	}

	if strings.HasPrefix(key, "h_") {
		return fl.headerL(key[3:])
	}

	if strings.HasPrefix(key, "a_") {
		return fl.argL(key[3:])
	}
	return nil
}

type elementL struct {
	null  bool
	value lua.LValue
	raw   string
}

func (el *elementL) String() string {
	if el.null {
		return ""
	}
	if len(el.raw) > 0 {
		return el.raw
	}

	el.raw = el.value.String()
	return el.raw
}

func (el *elementL) Type() lua.LValueType                   { return lua.LTObject }
func (el *elementL) AssertFloat64() (float64, bool)         { return 0, false }
func (el *elementL) AssertString() (string, bool)           { return "", false }
func (el *elementL) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (el *elementL) Peek() lua.LValue                       { return el }

func (el *elementL) doMatch(fn func(string) bool) bool {
	switch el.Type() {
	case lua.LTNil:
		return false
	case lua.LTTable:
		arr := el.value.(*lua.LTable).Array()
		if len(arr) == 0 {
			return false
		}

		for _, v := range arr {
			if fn(v.String()) {
				return true
			}
		}

		return false
	default:
		return fn(el.String())
	}
}

func (el *elementL) equalL(L *lua.LState) int {
	if el.null {
		L.Push(lua.LFalse)
		return 1
	}

	ret := false
	L.Callback(func(val lua.LValue) (stop bool) {

		match := func(data string) bool {
			return val.String() == data
		}
		ret = el.doMatch(match)

		return ret
	})

	L.Push(lua.LBool(ret))
	return 1
}

func (el *elementL) regexL(L *lua.LState) int {

	if el.null {
		L.Push(lua.LFalse)
		return 1
	}
	ret := false

	L.Callback(func(val lua.LValue) (stop bool) {
		if val.Type() != lua.LTString {
			return false
		}

		regex := val.String()
		match := func(data string) bool {
			ok, err := regexp.MatchString(regex, data)
			if err != nil {
				log.Errorf("regex %s fail %v", data, err)
				return false
			}
			return ok
		}

		ret = el.doMatch(match)

		return ret
	})

	L.Push(lua.LBool(ret))
	return 1
}

func (el *elementL) Index(L *lua.LState, key string) lua.LValue {

	switch key {
	case "eq", "equal":
		return lua.NewFunction(el.equalL)

	case "re", "regex":
		return lua.NewFunction(el.regexL)

	case "length":
		if el.null {
			return lua.LInt(0)
		}
		return lua.LInt(len(el.String()))

	case "have":
		if el.null {
			return lua.LFalse
		}

		if len(el.String()) == 0 {
			return lua.LFalse
		}

		return lua.LTrue

	default:
		return lua.LNil

	}

}
