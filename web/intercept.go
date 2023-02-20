package web

type Interceptor struct {
	enable byte
}

func (i *Interceptor) bytes() []byte {
	return []byte{i.enable}
}

func (i *Interceptor) Enable() bool {
	return i.enable == 1
}
