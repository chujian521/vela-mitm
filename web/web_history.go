package web

import (
	"github.com/vela-ssoc/vela-kit/auxlib"
	"net/http"
)

func (web *WebAddon) auth(r *http.Request) (bool, *FlowDB) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return false, nil
	}

	size := len(web.conns)
	if size == 0 {
		return false, nil
	}

	for i := 0; i < size; i++ {
		conn := web.conns[i]
		if conn.userData.Token == token {
			return true, conn.db
		}
	}
	return false, nil
}

func (web *WebAddon) MitmHistoryPull(w http.ResponseWriter, r *http.Request, db *FlowDB) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	page := auxlib.ToInt(r.URL.Query().Get("page"))
	pageSize := auxlib.ToInt(r.URL.Query().Get("pagesize"))

	skip := (page - 1) * pageSize
	if page < 1 || pageSize <= 0 {
		Bad(w, http.StatusNotFound, "page number fail page:%v page_size:%d", page, pageSize)
		return
	}

	w.Write(db.History(skip, pageSize))
}

func (web *WebAddon) MitmHistoryClear(w http.ResponseWriter, r *http.Request, db *FlowDB) {

	//w.Header().Set("Content-Type", "application/json")
	if err := db.Reset(); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
