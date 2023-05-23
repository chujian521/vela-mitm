package web

import (
	"fmt"
	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/q"
	"github.com/bytedance/sonic"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-mitm/proxy"
	"go.etcd.io/bbolt"
	"os"
	"sync"
)

type FlowDB struct {
	mu         sync.Mutex
	options    *bbolt.Options
	FlowBucket string
	FlowMgrBkt string
	Path       string
	db         *storm.DB
}

func (fdb *FlowDB) close() {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	if err := fdb.db.Close(); err != nil {
		log.Errorf("close %s fail %v", fdb.Path, err)
	}
}

func (fdb *FlowDB) Reset() error {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	if err := fdb.db.Close(); err != nil {
		log.Errorf("flow db close fail %v", err)
		return err
	}

	if err := os.Remove(fdb.Path); err != nil {
		log.Errorf("flow db close fail %v", err)
		return err
	}

	fdb.open()

	return nil
}

func (fdb *FlowDB) FindFlowId(id string) (*Flow, error) {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	var flow Flow
	if id == "" {
		return nil, fmt.Errorf("empty id")
	}

	bkt := fdb.db.From(fdb.FlowBucket)

	err := bkt.One("FlowID", id, &flow)
	if err != nil {
		return nil, err
	}

	return &flow, nil
}

type FlowStatMgr struct {
	Total   int `json:"total"`
	Http200 int `json:"http_200"`
	Http30x int `json:"http_30x"`
	Http40x int `json:"http_40x"`
	Http50x int `json:"http_50x"`
}

type HistoryMgr struct {
	FlowStatMgr
	Flows []FlowSimple `json:"flows"`
}

func (fdb *FlowDB) IncrFlowStatus(flow *Flow) {
	bkt := fdb.db.From(fdb.FlowMgrBkt)
	fsm := &FlowStatMgr{}

	bkt.Get(fdb.FlowMgrBkt, "flow-mgr", fsm)
	fsm.Total++
	if flow.StatusCode == 200 {
		fsm.Http200++
		goto done
	}
	if flow.StatusCode > 300 && flow.StatusCode < 399 {
		fsm.Http30x++
		goto done
	}

	if flow.StatusCode > 400 && flow.StatusCode < 499 {
		fsm.Http40x++
		goto done
	}

	if flow.StatusCode > 500 && flow.StatusCode < 599 {
		fsm.Http50x++
		goto done
	}

done:
	if e := bkt.Set(fdb.FlowMgrBkt, "flow-mgr", fsm); e != nil {
		log.Errorf("bucket set flow stat fail %v", e)
	}
}

func (fdb *FlowDB) History(skip, size int) []byte {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	var history HistoryMgr
	var fsm FlowStatMgr
	bkt := fdb.db.From(fdb.FlowMgrBkt)
	bkt.Get(fdb.FlowMgrBkt, "flow-mgr", &fsm)

	var flows []Flow
	bkt = fdb.db.From(fdb.FlowBucket)
	err := bkt.Select(q.Not(q.Eq("Method", "CONNECT"))).Reverse().Skip(skip).Limit(size).Find(&flows)
	if err != nil {
		log.Errorf("read all fail %v", err)
		goto DONE
	}

	if len(flows) == 0 {
		history.Flows = []FlowSimple{}
		goto DONE
	}

	history.Flows = make([]FlowSimple, len(flows))

	for i := 0; i < len(flows); i++ {
		history.Flows[i] = flows[i].ToSimple()
	}

DONE:
	history.Total = fsm.Total
	history.Http200 = fsm.Http200
	history.Http30x = fsm.Http30x
	history.Http40x = fsm.Http40x
	history.Http50x = fsm.Http50x
	chunk, _ := sonic.Marshal(history)

	return chunk
}

func (fdb *FlowDB) UpsertFlow(msg *messageFlow, f *proxy.Flow) {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	if fdb.db == nil {
		return
	}

	bkt := fdb.db.From(fdb.FlowBucket)
	flow := ToFlow(msg, f, false)
	flow.ParseURL()
	if e := bkt.Save(flow); e != nil {
		log.Errorf("save flow fail %v", e)
	} else {
		fdb.IncrFlowStatus(flow)
	}
}

func (fdb *FlowDB) open() {

	opt := &bbolt.Options{
		Timeout:      0,
		NoGrowSync:   false,
		NoSync:       true,
		FreelistType: bbolt.FreelistMapType,
	}

	//新建数据存储
	db, err := storm.Open(fdb.Path, storm.BoltOptions(0600, opt), storm.Codec(SonicCodec))
	if err != nil {
		log.Errorf("open flow db fail %v", err)
		return
	}

	fdb.db = db
	fdb.options = opt
}

func NewFlowDB(name string) *FlowDB {
	flowDb := &FlowDB{
		FlowBucket: "flow",
		FlowMgrBkt: "flow-mgr",
		Path:       fmt.Sprintf("flow.%s.db", name),
	}

	flowDb.open()
	return flowDb
}
