package main

import (
	"flag"
	"fmt"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"github.com/vela-ssoc/vela-mitm/web"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
)

type config struct {
	Addr   string   `yaml:"addr"`
	Port   int      `yaml:"port"`
	Large  int      `yaml:"large"`
	Name   string   `yaml:"name"`
	Pass   string   `yaml:"pass"`
	Origin []string `yaml:"origin"`
	Mode   string   `default:"proxy" yaml:"mode"`
}

var f = fmt.Sprintf

func (cfg *config) ProxyListen() string {
	return f("%s:%d", cfg.Addr, cfg.Port)
}

func (cfg *config) WebListen() string {
	return f("%s:%d", cfg.Addr, cfg.Port+1)
}

func (cfg *config) Cert() string {
	return "cert.d"
}

func init() {
	//flag.IntVar(&cfg.Port, "port", 9080, "listen port")
	//flag.StringVar(&cfg.Addr, "bind", "", "bind addr")
	//flag.IntVar(&cfg.Large, "large", 1024*1024*5, "stream large body")
	//flag.StringVar(&cfg.Name, "name", "", "账户")
	//flag.StringVar(&cfg.Pass, "pass", "", "密码")
	//flag.Parse()

}

var defaultMitm = &config{
	Addr:   "0.0.0.0",
	Port:   9080,
	Large:  1024 * 1024 * 5,
	Name:   "mitm",
	Pass:   uuid.NewV4().String()[:8],
	Origin: []string{"http://127.0.0.1", "https://127.0.0.1"},
}

func SaveDefaultConfig(fd *os.File) {
	chunk, err := yaml.Marshal(defaultMitm)
	if err != nil {
		log.Errorf("save mitm config fail %v", err)
		return
	}

	_, err = fd.Write(chunk)
	if err != nil {
		log.Errorf("save mitm config fail %v", err)
		return
	}
}

func LoadConfig(path string) (*config, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	s, _ := file.Stat()
	if s.Size() == 0 {
		SaveDefaultConfig(file)
		return defaultMitm, nil
	}

	chunk, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var conf config
	err = yaml.Unmarshal(chunk, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

func main() {

	path := flag.String("c", "mitm.yaml", "默认配置信息")

	cfg, err := LoadConfig(*path)
	if err != nil {
		log.Errorf("load mitm config fail %v", err)
		return
	}

	opts := &proxy.Options{
		Mode:              cfg.Mode,
		SslInsecure:       true,
		Addr:              cfg.ProxyListen(),
		StreamLargeBodies: int64(cfg.Large),
		CaRootPath:        cfg.Cert(),
		Upstream: func(r *http.Request, p *proxy.Proxy) string {
			peer := r.Header.Get("X-Mitmproxy-Peer")
			if len(peer) == 0 {
				return ""
			}

			return fmt.Sprintf("%s://%s", r.URL.Scheme, peer)
		},
	}

	if cfg.Name == "" || cfg.Pass == "" {
		log.Fatal("not found user or pass")
		return
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(web.NewWebAddon(web.Config{
		Addr:   cfg.WebListen(),
		Name:   cfg.Name,
		Pass:   cfg.Pass,
		Origin: cfg.Origin,
	}))
	log.Fatal(p.Start())
}
