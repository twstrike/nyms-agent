package pipes

import (
	"fmt"
	"io"
	"log"
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

func RunPipeServer(r io.ReadCloser, w io.WriteCloser, protoDebug bool) {
	pp, err := createPipePair(r, w, protoDebug)
	defer pp.Close()
	protocol := new(protocol.Protocol)
	rpc.Register(protocol)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to create pipe pair: %s", err))
		return
	}
	codec := jsonrpc.NewServerCodec(pp)
	log.Println("Starting...")
	rpc.ServeCodec(codec)
}

func NewClient(r io.ReadCloser, w io.WriteCloser, protoDebug bool) *rpc.Client {
	pp, _ := createPipePair(r, w, protoDebug)
	return jsonrpc.NewClient(pp)
}

func createPipePair(r io.ReadCloser, w io.WriteCloser, protoDebug bool) (io.ReadWriteCloser, error) {
	return &pipePair{r, w}, nil
}
