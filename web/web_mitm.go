package web

import (
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type UserData struct {
	Name  string
	Token string
	Time  time.Time
}

func (web *WebAddon) Login(r *http.Request) (bool, *UserData) {
	query := r.URL.Query()
	pass := query.Get("id")

	if pass == web.config.Pass {
		return true, &UserData{
			Name:  web.config.Name,
			Token: uuid.NewV4().String(),
			Time:  time.Now(),
		}
	}

	return false, nil
}

func (web *WebAddon) MitmConnect(w http.ResponseWriter, r *http.Request) {
	ok, ud := web.Login(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("check you login info"))
		log.Errorf("web %s connect fail", web.config.Name)
		return
	}

	c, err := web.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := newConn(c, ud)
	web.addConn(conn)

	defer func() {
		web.removeConn(conn)
		c.Close()
	}()

	err = conn.conn.WriteMessage(websocket.BinaryMessage, NewLogonMessage(EmptyID, ud.Token))
	if err != nil {
		log.Errorf("send login token fail: %v", err)
		return
	}

	conn.readloop()

}

func (web *WebAddon) MitmDummyCert(w http.ResponseWriter, r *http.Request, db *FlowDB) {
	cer, err := os.ReadFile(filepath.Join("cert.d/mitmproxy-ca-cert.cer"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(cer)
	return
}
