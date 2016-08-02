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
var daemonEnabled bool
var guiEnabled bool
var protoDebug bool

func init() {
	flag.BoolVar(&pipe, "pipe", false, "Run RPC service on stdin/stdout")
	flag.BoolVar(&daemonEnabled, "d", false, "Run RPC service on unix domain socket")
	flag.BoolVar(&guiEnabled, "g", false, "Run gui client")
	flag.BoolVar(&protoDebug, "protoDebug", false, "Log RPC traffic")
	flag.Parse()
}

func main() {
	if pipe {
		go keymgr.LoadDefaultKeyring()
		pp := pipes.CreatePipePair(os.Stdin, os.Stdout, protoDebug)
		defer pp.Close()
		log.Println("Listening on Stdin ...")
		for {
			go pipes.Serve(pp, protoDebug)
		}
	} else if daemonEnabled {
		go keymgr.LoadDefaultKeyring()
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
	} else if guiEnabled {
		runClient()
	}
}
