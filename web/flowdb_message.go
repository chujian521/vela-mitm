package web

import (
	"github.com/bytedance/sonic"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"net/http"
	"net/url"
	"time"
)

var EmptyID = "00000000-0000-0000-0000-000000000000"

type ClientConn struct {
	Address string `json:"address" storm:"address"`
	Tls     bool   `json:"tls"    storm:"tls"`
}
type ServerConn struct {
	Address string `json:"address" storm:"address"`
	Peer    string `json:"peer" storm:"peer"`
}

type Connection struct {
	ID         string     `json:"id" storm:"id"`
	ClientConn ClientConn `json:"client_conn"`
	ServerConn ServerConn `json:"server_conn"`
}

func (c *Connection) bytes() []byte {
	chunk, err := sonic.Marshal(c)
	if err != nil {
		log.Errorf("connect marshal fail %v", err)
	}
	return chunk
}

func (c *Connection) clone(cnn *proxy.ConnContext) {
	c.ID = cnn.Id().String()
	//c.ClientConn.Id = cnn.ClientConn.Id.String()
	c.ClientConn.Address = cnn.ClientConn.Conn.RemoteAddr().String()
	c.ClientConn.Tls = cnn.ClientConn.Tls

	//c.ServerConn.Id = cnn.ServerConn.Id.String()
	c.ServerConn.Address = cnn.ServerConn.Address
	c.ServerConn.Peer = cnn.ServerConn.Conn.RemoteAddr().String()
}

type Request struct {
	ConnId     string      `json:"connId"`
	Connection Connection  `json:"connecton"`
	Method     string      `json:"method"`
	Proto      string      `json:"proto"`
	Header     http.Header `json:"header"`
	RawURL     string      `json:"rawURL"`
	Time       time.Time   `json:"time"`
}

func (f *Flow) ParseURL() {
	if f.ClientTls {
		f.Scheme = "https"
	} else {
		f.Scheme = "http"

	}

	u, _ := url.Parse(f.RawURL)
	if f.Scheme == "" {
		f.URL = "//" + u.Host + u.Path
	} else {
		f.URL = f.Scheme + "://" + u.Host + u.Path
	}

	f.Query = u.RawQuery
}

type Response struct {
	StatusCode int         `json:"status_code"`
	Proto      string      `json:"proto"`
	Header     http.Header `header`
}

type Flow struct {
	ID     int         `storm:"id,increment"`
	FlowID string      `json:"flow_id" storm:"index,unique"`
	Wait   bool        `json:"wait"`
	MType  messageType `json:"type"`

	//request
	Method        string      `json:"method"`
	Scheme        string      `json:"scheme"`
	Proto         string      `json:"proto"`
	RequestHeader http.Header `json:"request_header"`
	RawURL        string      `json:"rawURL"`
	URL           string      `json:"url"`
	Query         string      `json:"query"`
	RequestBody   string      `json:"request_body"`

	//connect
	ConnId        string `json:"connId"`
	ClientAddress string `json:"client_address"`
	ClientTls     bool   `json:"client_tls"`
	ServerAddress string `json:"server_address"`
	ServerPeer    string `json:"server_peer"`

	//response
	ResponseHeader http.Header `json:"response_header"`
	ResponseBody   string      `json:"response_body"`
	StatusCode     int         `json:"status_code"`
	ResponseSize   int         `json:"response_size"`

	Time time.Time `json:"time"`
}

func (f *Flow) ToSimple() FlowSimple {
	return FlowSimple{
		ID:     f.ID,
		FlowID: f.FlowID,
		Wait:   f.Wait,
		MType:  f.MType,

		//request,
		Method:      f.Method,
		Scheme:      f.Scheme,
		Proto:       f.Proto,
		RawURL:      f.RawURL,
		URL:         f.URL,
		Query:       f.Query,
		RequestBody: f.RequestBody,

		//connect,
		ConnId:        f.ConnId,
		ClientAddress: f.ClientAddress,
		ClientTls:     f.ClientTls,
		ServerAddress: f.ServerAddress,
		ServerPeer:    f.ServerPeer,

		//response,
		StatusCode:   f.StatusCode,
		ResponseSize: f.ResponseSize,
		Time:         f.Time.Unix(),
	}

}

type FlowSimple struct {
	ID     int         `json:"id"`
	FlowID string      `json:"flow_id"`
	Wait   bool        `json:"wait"`
	MType  messageType `json:"type"`

	//request
	Method      string `json:"method"`
	Scheme      string `json:"scheme"`
	Proto       string `json:"proto"`
	RawURL      string `json:"rawURL"`
	URL         string `json:"url"`
	Query       string `json:"query"`
	RequestBody string `json:"request_body"`

	//connect
	ConnId        string `json:"connId"`
	ClientAddress string `json:"client_address"`
	ClientTls     bool   `json:"client_tls"`
	ServerAddress string `json:"server_address"`
	ServerPeer    string `json:"server_peer"`

	//response
	StatusCode   int   `json:"status_code"`
	ResponseSize int   `json:"response_size"`
	Time         int64 `json:"time"`
}

func (f *Flow) Uncompress() *Flow {

	f.RequestBody = UncompressedBody(f.RequestHeader, auxlib.S2B(f.RequestBody))
	f.ResponseBody = UncompressedBody(f.ResponseHeader, auxlib.S2B(f.ResponseBody))
	return f
}

func (f *Flow) Bytes() []byte {
	chunk, _ := sonic.Marshal(f)
	return chunk
}

func (f *Flow) Decode(chunk []byte) error {
	if len(chunk) == 0 {
		return nil
	}

	return sonic.Unmarshal(chunk, f)
}

func (f *Flow) WithServerPeer(pf *proxy.Flow) {
	if pf.ConnContext.ServerConn == nil {
		peer := pf.Request.Header.Get("X-Mitmproxy-Peer")
		if len(peer) != 0 {
			f.ServerPeer = peer
		}
		return
	}

	f.ServerAddress = pf.ConnContext.ServerConn.Address
	f.ServerPeer = pf.ConnContext.ServerConn.Conn.RemoteAddr().String()
}

func (f *Flow) WithResponse(pf *proxy.Flow, decompress bool) {
	f.StatusCode = pf.Response.StatusCode
	f.ResponseHeader = pf.Response.Header
	if decompress {
		f.ResponseBody = UncompressedBody(pf.Response.Header, pf.Response.Body)
	} else {
		f.ResponseBody = auxlib.B2S(pf.Response.Body)
	}

	f.ResponseSize = len(f.ResponseBody)

}

func ToFlow(msg *messageFlow, f *proxy.Flow, decompress bool) *Flow {
	connId := f.ConnContext.Id().String()
	flow := &Flow{
		MType:         msg.mType,
		FlowID:        msg.id.String(),
		ConnId:        connId,
		Method:        f.Request.Method,
		Proto:         f.Request.Proto,
		RequestHeader: f.Request.Header,
		RawURL:        f.Request.URL.String(),
		ClientAddress: f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
		ClientTls:     f.ConnContext.ClientConn.Tls,
		RequestBody:   auxlib.B2S(f.Request.Body),
		Time:          time.Now(),
	}

	flow.ParseURL()
	flow.WithServerPeer(f)

	if msg.mType == messageTypeResponseBody {
		flow.WithResponse(f, decompress)
	}

	return flow
}
