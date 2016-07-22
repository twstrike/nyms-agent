package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/nyms-agent/pipes"
)

var pipe bool
var daemon bool
var protoDebug bool

func init() {
	flag.BoolVar(&pipe, "pipe", false, "Run RPC service on stdin/stdout")
	flag.BoolVar(&daemon, "daemon", false, "Run RPC service on unix domain socket")
	flag.BoolVar(&protoDebug, "debug", false, "Log RPC traffic")
	flag.Parse()
}

func main() {
	keymgr.LoadDefaultKeyring()
	if pipe {
		pipes.RunPipeServer(os.Stdin, os.Stdout, protoDebug)
		return
	} else if daemon {
		l, err := net.Listen("unix", "/tmp/nyms")
		defer l.Close()
		if err != nil {
			log.Fatal(err)
		}
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		pipes.RunPipeServer(conn, conn, protoDebug)
	}
}
