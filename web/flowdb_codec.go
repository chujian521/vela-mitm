package web

import (
	"github.com/bytedance/sonic"
)

var SonicCodec = new(SonicJsonCodec)

type SonicJsonCodec int

func (j SonicJsonCodec) Marshal(v interface{}) ([]byte, error) {
	return sonic.Marshal(v)
}

func (j SonicJsonCodec) Unmarshal(b []byte, v interface{}) error {
	return sonic.Unmarshal(b, v)
}

func (j SonicJsonCodec) Name() string {
	return "sonic-json"
}
