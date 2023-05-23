package web

import "net/http"

func (web *WebAddon) MitmFlowPull(w http.ResponseWriter, r *http.Request, db *FlowDB) {
	flowId := r.URL.Query().Get("flow")
	flow, err := db.FindFlowId(flowId)
	if err != nil {
		Bad(w, http.StatusNotFound, err.Error())
		return
	}

	JSON(w, flow.Uncompress().Bytes())
}
