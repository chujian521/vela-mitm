package web

import (
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/lua"
)

func flowContextIndexL(L *lua.LState, key string) lua.LValue {
	fl, ok := L.Exdata.(*flowL)
	if !ok {
		log.Error("invalid flowL with lua vm")
		return lua.LNil
	}

	switch key {
	case "wait":
		return lua.NewFunction(fl.waitL)
	case "pass":
		return lua.NewFunction(fl.passL)
	case "have":
		return lua.NewFunction(fl.containL)
	default:
		v := fl.Index(L, key)
		if v == nil {
			return &elementL{null: true}
		}

		if v.Type() == lua.LTNil {
			return &elementL{null: true}
		}
		return &elementL{value: v}

	}

}
