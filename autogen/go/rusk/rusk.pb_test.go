package rusk_test

import (
	"testing"

	"github.com/dusk-network/dusk-protobuf/autogen/go/rusk"
	"google.golang.org/protobuf/proto"
)

func TestProto(t *testing.T) {

	r := new(rusk.ContractCallTx_Tx)

	bb, _ := proto.Marshal(r)
	br := new(rusk.ContractCallTx_Tx)
	proto.Unmarshal(bb, br)
}
