package web

import (
	"embed"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"io/fs"
	"net/http"
)

//go:embed client/build
var assets embed.FS

func (web *WebAddon) HaveOrigin(origin string) bool {
	if len(web.config.Origin) == 0 || len(origin) == 0 {
		return false
	}

	for _, item := range web.config.Origin {
		if item == origin {
			return true
		}
	}

	return false

}

func (web *WebAddon) HandleFunc(next func(w http.ResponseWriter, r *http.Request, fdb *FlowDB)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if web.HaveOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		ok, db := web.auth(r)
		if !ok {
			Unauthorized(w, r)
			return
		}

		next(w, r, db)
	}
}

func (web *WebAddon) Router() *http.ServeMux {
	serverMux := new(http.ServeMux)
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/connect", web.MitmConnect)
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/history/pull", web.HandleFunc(web.MitmHistoryPull))
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/flow/pull", web.HandleFunc(web.MitmFlowPull))
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/history/clear", web.HandleFunc(web.MitmHistoryClear))
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/proxy/repeat", web.HandleFunc(web.MitmProxyRequest))
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/proxy/intruder", web.HandleFunc(web.MitmProxyIntruder))
	serverMux.HandleFunc("/mitm/"+web.config.Name+"/dummy/cert", web.HandleFunc(web.MitmDummyCert))

	fsys, err := fs.Sub(assets, "client/build")
	if err != nil {
		panic(err)
	}

	serverMux.Handle("/", http.FileServer(http.FS(fsys)))
	return serverMux
}

func (web *WebAddon) ListenServer(addr string) {
	web.upgrader = &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	server := &http.Server{Addr: addr, Handler: web.Router()}

	go func() {
		log.Infof("web interface start listen at %v\n", addr)
		err := server.ListenAndServe()
		log.Error(err)
	}()

}
