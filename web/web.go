package web

import (
	"github.com/gorilla/websocket"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"sync"
)

type WebAddon struct {
	proxy.BaseAddon
	upgrader *websocket.Upgrader

	conns   []*concurrentConn
	connsMu sync.RWMutex

	config Config
}

func NewWebAddon(cfg Config) *WebAddon {
	web := new(WebAddon)
	web.conns = make([]*concurrentConn, 0)
	web.config = cfg
	web.ListenServer(cfg.Addr)
	return web
}
func (web *WebAddon) disconnect(name string) {
	for _, conn := range web.conns {
		if conn.userData.Name == name {
			web.removeConn(conn)
		}
	}
}

func (web *WebAddon) addConn(c *concurrentConn) {

	web.disconnect(c.userData.Name)

	web.connsMu.Lock()
	web.conns = append(web.conns, c)
	c.OpenDB(web.config.Name)
	web.connsMu.Unlock()
}

func (web *WebAddon) removeConn(conn *concurrentConn) {
	web.connsMu.Lock()
	defer web.connsMu.Unlock()

	index := -1
	for i, c := range web.conns {
		if conn == c {
			index = i
			c.db.close()
			c.interceptorClear()
			break
		}
	}

	if index == -1 {
		return
	}
	web.conns = append(web.conns[:index], web.conns[index+1:]...)
}

func (web *WebAddon) forEachConn(do func(c *concurrentConn)) bool {
	web.connsMu.RLock()
	conns := web.conns
	web.connsMu.RUnlock()
	if len(conns) == 0 {
		return false
	}
	for _, c := range conns {
		do(c)
	}
	return true
}

func (web *WebAddon) sendFlow(f *proxy.Flow, msgFn func() *messageFlow) bool {
	web.connsMu.RLock()
	conns := web.conns
	web.connsMu.RUnlock()

	if len(conns) == 0 {
		return false
	}

	msg := msgFn()
	for _, c := range conns {
		c.writeMessage(msg, f)
	}

	return true
}

func (web *WebAddon) Requestheaders(f *proxy.Flow) {
	web.sendFlow(f, func() *messageFlow {
		return newMessageFlow(messageTypeRequest, f)
	})
}

func (web *WebAddon) Request(f *proxy.Flow) {

	web.sendFlow(f, func() *messageFlow {
		return newMessageFlow(messageTypeRequestBody, f)
	})
}

func (web *WebAddon) Responseheaders(f *proxy.Flow) {
	web.sendFlow(f, func() *messageFlow {
		return newMessageFlow(messageTypeResponse, f)
	})
}

func (web *WebAddon) Response(f *proxy.Flow) {

	web.sendFlow(f, func() *messageFlow {
		return newMessageFlow(messageTypeResponseBody, f)
	})
}

func (web *WebAddon) ServerDisconnected(connCtx *proxy.ConnContext) {
	//web.forEachConn(func(c *concurrentConn) {
	//	c.whenConnClose(connCtx)
	//})
}
