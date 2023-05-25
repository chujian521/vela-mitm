package web

import (
	"fmt"
	"github.com/bytedance/sonic/decoder"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"net/http"
	"strings"
)

func (web *WebAddon) MitmProxyIntruder(w http.ResponseWriter, r *http.Request, db *FlowDB) {
	var fr proxy.RequestEditData
	err := decoder.NewStreamDecoder(r.Body).Decode(&fr)
	fmt.Println(fr.Body)
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
