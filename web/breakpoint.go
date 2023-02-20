package web

import (
	log "github.com/sirupsen/logrus"
	cond "github.com/vela-ssoc/vela-cond"
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

type breakPointRule struct {
	Method    string `json:"method"`
	Condition string `json:"condit"`
	Script    string `json:"script"`
	Action    int    `json:"action"` // 1 - change request 2 - change response 3 - both

	cond   *cond.Cond     `json:"-"`
	script *lua.LFunction `json:"-"`
}

func (rule *breakPointRule) parse() {
	cnd := strings.Split(rule.Condition, "\n")
	rule.cond = cond.New(cnd...)

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

func (rule *breakPointRule) Match(fl *flowL) bool {
	if rule.Method != "" && rule.Method != fl.flow.Request.Method {
		return false
	}

	if rule.cond.Len() > 0 && !rule.cond.Match(fl) {
		return false
	}

	return rule.call(fl)
}
