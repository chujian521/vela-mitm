package web

import (
	"context"
	"github.com/bytedance/sonic/decoder"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"net"
	"net/http"
	"strings"
	"time"
)

func NewTransport(peer string) http.RoundTripper {
	if peer == "" {
		return nil
	}

	// 定义TCP连接超时时间
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, peer)
	}

	Transport := &http.Transport{
		DialContext:         dialContext,
		DisableKeepAlives:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return Transport
}

func (web *WebAddon) MitmProxyRequest(w http.ResponseWriter, r *http.Request, db *FlowDB) {
	var fr proxy.RequestEditData
	err := decoder.NewStreamDecoder(r.Body).Decode(&fr)
	if err != nil {
		Bad(w, http.StatusServiceUnavailable, "decode fail %v", err)
		return
	}

	request, err := http.NewRequest(fr.Method, fr.RawURL, strings.NewReader(fr.Body))
	if err != nil {
		Bad(w, http.StatusServiceUnavailable, "decode fail %v", err)
		return
	}

	request.Header = fr.Header

	peer := request.Header.Get("X-Mitmproxy-Peer")

	client := &http.Client{}
	if tp := NewTransport(peer); tp != nil {
		client.Transport = tp
	}

	resp, err := client.Do(request)
	if err != nil {
		Bad(w, http.StatusServiceUnavailable, "http request fail %v", err)
		return

	}

	flow := &Flow{
		Proto:          resp.Proto,
		StatusCode:     resp.StatusCode,
		ResponseHeader: resp.Header,
	}

	flow.ResponseBody = UncompressResponse(resp)
	flow.ResponseSize = len(flow.ResponseBody)

	JSON(w, flow.Bytes())
}
