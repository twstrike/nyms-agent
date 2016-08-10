package pipes

import (
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/twstrike/nyms-agent/protocol"
)

type pipePair struct {
	input  io.ReadCloser
	output io.WriteCloser
}

func (pp pipePair) Read(p []byte) (int, error) {
	return pp.input.Read(p)
}

func (pp pipePair) Write(p []byte) (int, error) {
	return pp.output.Write(p)
}

func (pp pipePair) Close() (e error) {
	if err := pp.input.Close(); err != nil {
		e = err
	}

	if err := pp.output.Close(); err != nil && e == nil {
		e = err
	}

	return e
}

func Serve(conn io.ReadWriteCloser) {
	defer conn.Close()
	protocol := new(protocol.Protocol)
	rpc.Register(protocol)
	codec := jsonrpc.NewServerCodec(conn)
	rpc.ServeCodec(codec)
}

func NewClient(conn io.ReadWriteCloser) *rpc.Client {
	return jsonrpc.NewClient(conn)
}

func CreatePipePair(r io.ReadCloser, w io.WriteCloser) io.ReadWriteCloser {
	return &pipePair{r, w}
}
