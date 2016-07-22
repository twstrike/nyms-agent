package client

import (
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/twstrike/nyms-agent/pipes"
)

func NewClient(r io.ReadCloser, w io.WriteCloser, protoDebug bool) *rpc.Client {
	pp, _ := pipes.CreatePipePair(r, w, protoDebug)
	return jsonrpc.NewClient(pp)
}
