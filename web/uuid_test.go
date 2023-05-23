package web

import (
	uuid "github.com/satori/go.uuid"
	"testing"
)

func TestUUID(t *testing.T) {
	print(uuid.NewV4().String())
}
