package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"github.com/vela-ssoc/vela-mitm/web"
	"net/http"
)

type config struct {
	Addr  string
	Port  int
	Large int
}

var cfg = config{}

func (cfg *config) ProxyListen() string {
	return f("%s:%d", cfg.Addr, cfg.Port)
}

func (cfg *config) WebListen() string {
	return f("%s:%d", cfg.Addr, cfg.Port+1)
}

var f = fmt.Sprintf

func main() {

	flag.IntVar(&cfg.Port, "port", 9080, "listen port")
	flag.StringVar(&cfg.Addr, "bind", "", "bind addr")
	flag.IntVar(&cfg.Large, "large", 1024*1024*5, "stream large body")
	flag.Parse()

	opts := &proxy.Options{
		Addr:              cfg.ProxyListen(),
		StreamLargeBodies: int64(cfg.Large),
		Upstream: func(r *http.Request, p *proxy.Proxy) string {
			peer := r.Header.Get("X-Mitmproxy-Peer")
			if len(peer) == 0 {
				return ""
			}

			return fmt.Sprintf("%s://%s", r.URL.Scheme, peer)
		},
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(web.NewWebAddon(cfg.WebListen()))
	log.Fatal(p.Start())
}
