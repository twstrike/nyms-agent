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
		pp := pipes.CreatePipePair(os.Stdin, os.Stdout, protoDebug)
		defer pp.Close()
		log.Println("Listening on Stdin ...")
		for {
			go pipes.Serve(pp, protoDebug)
		}
	} else if daemon {
		log.Println("Listening on /tmp/nyms.sock ...")
		l, err := net.Listen("unix", "/tmp/nyms.sock")
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go pipes.Serve(conn, protoDebug)
		}
	}
}
