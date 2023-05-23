package web

import (
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/lua"
	"strings"
	"sync"
)

var ruleLuaCoroutinePool = &sync.Pool{
	New: func() interface{} {
		co := lua.NewState()
		co.SetGlobal("flow", lua.NewExport("mitm.flow.export", lua.WithIndex(flowContextIndexL)))

		return co
	},
}

type Condition struct {
	Key    string `json:"key"`
	Method string `json:"method"`
	Data   string `json:"data"`
}

type breakPointRule struct {
	Enable    bool           `json:"enable"`
	IgnoreExt []string       `json:"IgnoreExt"`
	Method    []string       `json:"Method"`
	Cnd       []Condition    `json:"Condition"`
	Script    string         `json:"Script"`
	Phase     []string       `json:"Phase"` // 1 - change request 2 - change response 3 - both
	script    *lua.LFunction `json:"-"`
}

func (rule *breakPointRule) parse() {
	//cnd := strings.Split(rule.Condition, "\n")
	//rule.cond = cond.New(cnd...)

	co := ruleLuaCoroutinePool.Get().(*lua.LState)
	fn, err := co.LoadString(rule.Script)
	if err != nil {
		log.Errorf("rule compile fail %v", err)
		return

	}
	rule.script = fn
}

func (rule *breakPointRule) call(fl *flowL) bool {
	if rule.script == nil || len(rule.Script) == 0 {
		return true
	}

	co := ruleLuaCoroutinePool.Get().(*lua.LState)
	co.SetContext(fl.ctx)
	co.Exdata = fl
	defer func() {
		co.Exdata = nil
		co.SetContext(nil)
		ruleLuaCoroutinePool.Put(co)
	}()

	err := co.CallByParam(lua.P{
		Fn:      rule.script,
		Protect: true,
		NRet:    0,
	})

	if err != nil {
		log.Errorf("lua script call fail: %v\n", err)
	}

	return fl.wait
}

/*

ctx.host == "www.baidu.com"

*/

func (rule *breakPointRule) MatchPhase(phase string) bool {
	for _, item := range rule.Phase {
		if item == phase {
			return true
		}
	}

	return false
}

func (rule *breakPointRule) HitIgnoreExt(ext string) bool {
	if len(rule.IgnoreExt) == 0 {
		return false
	}

	for _, item := range rule.IgnoreExt {
		if item == ext {
			return true
		}
	}

	return false
}

func (rule *breakPointRule) HaveMethod(method string) bool {
	if len(rule.Method) == 0 {
		return false
	}

	for _, item := range rule.Method {

		if item == "ANY" || item == "any" {
			return true
		}

		if item == method {
			return true
		}
	}

	return false
}

func (rule *breakPointRule) CallCnd(cnd Condition, fl *flowL) bool {

	ret := false

	fn, isNot := ParseCndMethod(cnd.Method)

	data := strings.Split(cnd.Data, "\n")
	lv := fl.Index(nil, cnd.Key)
	for _, item := range data {
		if fn(lv.String(), item) {
			ret = true
			goto done
		}
	}

done:
	if isNot {
		return !ret
	}

	return ret
}

func (rule *breakPointRule) MatchCnd(fl *flowL) bool {
	if len(rule.Cnd) == 0 {
		return true
	}

	for _, cnd := range rule.Cnd {
		if rule.CallCnd(cnd, fl) {
			return true
		}
	}

	return false
}

func (rule *breakPointRule) Match(fl *flowL) bool {

	if rule.HitIgnoreExt(fl.Ext()) {
		return false
	}

	if !rule.HaveMethod(fl.flow.Request.Method) {
		return false
	}

	if !rule.MatchCnd(fl) {
		return false
	}

	return rule.call(fl)
}
