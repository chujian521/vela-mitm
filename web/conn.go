package web

import (
	"context"
	"sync"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-mitm/proxy"
)

type concurrentConn struct {
	conn *websocket.Conn
	mu   sync.Mutex

	sendConnMessageMap map[string]bool

	interceptor bool
	waitChans   map[string]chan interface{}
	waitQueue   map[string]*flowTx
	waitChansMu sync.Mutex

	breakPointRules []*breakPointRule
}

type flowTx struct {
	value *messageEdit
	ctx   context.Context
	stop  context.CancelFunc
}

func newConn(c *websocket.Conn) *concurrentConn {
	return &concurrentConn{
		conn:               c,
		sendConnMessageMap: make(map[string]bool),
		waitChans:          make(map[string]chan interface{}),
		waitQueue:          make(map[string]*flowTx),
	}
}

func (c *concurrentConn) interceptorClear() {
	n := len(c.waitQueue)
	if n == 0 {
		return
	}

	for key, tx := range c.waitQueue {
		log.Errorf("flow %s interceptor off", key)
		tx.value = &messageEdit{
			mType: messageTypeInterceptorOff,
		}
		tx.stop()
	}

}

func (c *concurrentConn) trySendConnMessage(f *proxy.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := f.ConnContext.Id().String()
	if send := c.sendConnMessageMap[key]; send {
		return
	}
	c.sendConnMessageMap[key] = true
	msg := newMessageFlow(messageTypeConn, f)
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	if err != nil {
		log.Error(err)
		return
	}
}

func (c *concurrentConn) whenConnClose(connCtx *proxy.ConnContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sendConnMessageMap, connCtx.Id().String())

	msg := newMessageConnClose(connCtx)
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	if err != nil {
		log.Error(err)
		return
	}
}

func (c *concurrentConn) writeMessage(msg *messageFlow, f *proxy.Flow) {
	if c.isIntercpt(f, msg) {
		msg.waitIntercept = 1
	}

	c.mu.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	c.mu.Unlock()
	if err != nil {
		log.Error(err)
		return
	}

	if msg.waitIntercept == 1 {
		c.waitIntercept(f, msg)
	}
}

func (c *concurrentConn) readloop() {
	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			log.Error(err)
			break
		}

		if mt != websocket.BinaryMessage {
			log.Warn("not BinaryMessage, skip")
			continue
		}

		msg := parseMessage(data)
		if msg == nil {
			log.Warn("parseMessage error, skip")
			continue
		}

		switch v := msg.(type) {
		case *messageEdit:
			tx := c.initWaitContext(v.id.String())
			tx.value = v
			tx.stop()

		case *messageMeta:
			c.breakPointRules = v.breakPointRules
		case *Interceptor:
			if v.Enable() == false && c.interceptor {
				c.interceptorClear()
			}
			c.interceptor = v.Enable()
		default:
			log.Warn("invalid message, skip")
		}
	}
}

func (c *concurrentConn) initWaitContext(key string) *flowTx {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	if ctx, ok := c.waitQueue[key]; ok {
		return ctx
	}

	ctx, cancel := context.WithCancel(context.Background())
	wCtx := &flowTx{
		ctx:  ctx,
		stop: cancel,
	}
	c.waitQueue[key] = wCtx

	return wCtx
}

func (c *concurrentConn) initWaitChan(key string) chan interface{} {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	if ch, ok := c.waitChans[key]; ok {
		return ch
	}
	ch := make(chan interface{})
	c.waitChans[key] = ch
	return ch
}

// 是否拦截
func (c *concurrentConn) isIntercpt(f *proxy.Flow, after *messageFlow) bool {

	var action int
	switch after.mType {
	case messageTypeRequestBody:
		if c.interceptor && f.Request.Method != "CONNECT" {
			return true
		}
		action = 1

	case messageTypeResponseBody:
		action = 2

	default:
		return false

	}

	if len(c.breakPointRules) == 0 {
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())

	fl := flowL{ctx: ctx, stop: cancel, flow: f, wait: false}
	for _, rule := range c.breakPointRules {
		if action&rule.Action == 0 {
			continue
		}

		if rule.Match(&fl) {
			return true
		}

		//if rule.Method != "" && rule.Method != f.Request.Method {
		//	continue
		//}

		//if rule.Host == "" {
		//	continue
		//}

		//if strings.Contains(f.Request.URL.String(), rule.Host) {
		//	return true
		//}
	}

	return false
}

// 拦截
func (c *concurrentConn) waitIntercept(f *proxy.Flow, after *messageFlow) {
	tx := c.initWaitContext(f.Id.String())
	<-tx.ctx.Done()
	msg := tx.value

	switch msg.mType {
	case messageTypeDropRequest, messageTypeDropResponse: // drop
		f.Response = &proxy.Response{
			StatusCode: 502,
		}
		return

	case messageTypeChangeRequest:
		f.Request.Method = msg.request.Method
		f.Request.URL = msg.request.URL
		f.Request.Header = msg.request.Header
		f.Request.Body = msg.request.Body

	case messageTypeChangeResponse:
		f.Response.StatusCode = msg.response.StatusCode
		f.Response.Header = msg.response.Header
		f.Response.Body = msg.response.Body
	case messageTypeInterceptorOff:
		//todo
	}
}
