package web

import (
	"context"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-mitm/proxy"
)

type concurrentConn struct {
	userData *UserData
	conn     *websocket.Conn
	mu       sync.Mutex

	db          *FlowDB
	interceptor bool
	waitChans   map[string]chan interface{}
	waitQueue   map[string]*flowTx
	waitChansMu sync.Mutex

	ctx        context.Context
	stop       context.CancelFunc
	breakPoint *breakPointRule
	history    *breakPointRule
}

type flowTx struct {
	value *messageEdit
	ctx   context.Context
	stop  context.CancelFunc
}

func newConn(c *websocket.Conn, ud *UserData) *concurrentConn {
	ctx, stop := context.WithCancel(context.Background())

	cnn := &concurrentConn{
		ctx:       ctx,
		stop:      stop,
		userData:  ud,
		conn:      c,
		waitChans: make(map[string]chan interface{}),
		waitQueue: make(map[string]*flowTx),
	}

	return cnn
}

func (c *concurrentConn) OpenDB(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.db = NewFlowDB(name)
}

func (c *concurrentConn) interceptorClear() {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	n := len(c.waitQueue)
	if n == 0 {
		return
	}

	//c.stop()

	for key, tx := range c.waitQueue {
		log.Errorf("flow %s interceptor off", key)
		tx.value = &messageEdit{
			mType: messageTypeInterceptorOff,
		}
		tx.stop()
	}

}

func (c *concurrentConn) whenConnClose(connCtx *proxy.ConnContext) {
	//c.mu.Lock()
	//defer c.mu.Unlock()

	//delete(c.sendConnMessageMap, connCtx.Id().String())

	//msg := newMessageConnClose(connCtx)
	//err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	//if err != nil {
	//	log.Error(err)
	//	return
	//}
}

func (c *concurrentConn) SendInterceptor(msg *messageFlow, f *proxy.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	chunk := ToFlow(msg, f, true).Bytes()
	err := c.conn.WriteMessage(websocket.BinaryMessage, NewBinMessage(msg.mType, msg.id.String(), 1, chunk))
	if err != nil {
		log.Error(err)
		return
	}

}

func (c *concurrentConn) writeMessage(msg *messageFlow, f *proxy.Flow) {
	if c.isIntercpt(f, msg) {
		msg.waitIntercept = 1
		c.SendInterceptor(msg, f)
	}

	if msg.mType == messageTypeResponseBody {
		ctx, cancel := context.WithCancel(c.ctx)
		fl := &flowL{ctx: ctx, stop: cancel, flow: f, wait: false}
		if c.history.Match(fl) {
			c.db.UpsertFlow(msg, f)
		}
	}

	if msg.waitIntercept == 1 {
		c.waitIntercept(f, msg)
	}
}

func (c *concurrentConn) SetRule(v *messageMeta) {

	if v.mType == messageTypeChangeBreakPointRules {
		c.breakPoint = v.rule
		if !c.breakPoint.Enable {
			c.interceptorClear()
		}
		return
	}

	if v.mType == MessageTypeChangeHistoryRules {
		c.history = v.rule
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

		if string(data) == "ping" {
			c.mu.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, []byte("pong"))
			c.mu.Unlock()
			if err != nil {
				log.Error(err)
			}
			continue
		}

		msg, err := parseMessage(data)
		if err != nil {
			log.Warnf("parseMessage error, skip error %v", err)
			continue
		}

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
			c.SetRule(v)

		default:
			log.Warn("invalid message, skip")
		}
	}
}

func (c *concurrentConn) pop(key string) {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	delete(c.waitQueue, key)
}

func (c *concurrentConn) initWaitContext(key string) *flowTx {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	if ctx, ok := c.waitQueue[key]; ok {
		return ctx
	}

	ctx, cancel := context.WithCancel(c.ctx)
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

	if c.breakPoint == nil {
		return false
	}

	//var action int
	var phase string
	switch after.mType {
	case messageTypeRequestBody:
		if c.interceptor && f.Request.Method != "CONNECT" {
			return true
		}
		//action = 1
		phase = "Request"

	case messageTypeResponseBody:
		//action = 2
		phase = "Response"

	default:
		return false

	}

	if !c.breakPoint.Enable {
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())

	fl := flowL{ctx: ctx, stop: cancel, flow: f, wait: false}

	if !c.breakPoint.MatchPhase(phase) {
		return false
	}

	if c.breakPoint.Match(&fl) {
		return true
	}

	return false
}

// 拦截
func (c *concurrentConn) waitIntercept(f *proxy.Flow, after *messageFlow) {
	tx := c.initWaitContext(f.Id.String())
	<-tx.ctx.Done()
	msg := tx.value
	c.pop(f.Id.String())

	switch msg.mType {
	case messageTypeDropRequest, messageTypeDropResponse: // drop
		f.Response = &proxy.Response{
			StatusCode: 502,
		}
		return

	case messageTypeChangeRequest, messageTypeChangeRequestV2:
		f.Request.Method = msg.request.Method
		f.Request.URL = msg.request.URL
		f.Request.Header = msg.request.Header
		f.Request.Body = msg.request.Body

	case messageTypeChangeResponse, messageTypeChangeResponseV2:
		if msg.response.StatusCode != 0 {
			f.Response.StatusCode = msg.response.StatusCode
		}

		f.Response.Header = msg.response.Header

		if len(msg.response.Body) > 0 {
			f.Response.Body = msg.response.Body
			f.Response.Header.Set("Content-Length", strconv.Itoa(len(msg.response.Body)))
		} else {
			f.Response.Body = nil
			f.Response.Header.Set("Content-Length", "0")
		}

		if f.Response.Header.Get("Content-Encoding") != "" {
			delete(f.Response.Header, "Content-Encoding")
		}

	case messageTypeInterceptorOff:
		//todo
	}
}
