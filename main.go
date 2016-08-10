package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/nyms-agent/pipes"
)

var pipe bool
var daemonEnabled bool
var guiEnabled bool

func init() {
	flag.BoolVar(&pipe, "pipe", false, "Run RPC service on stdin/stdout")
	flag.BoolVar(&daemonEnabled, "d", false, "Run RPC service on unix domain socket")
	flag.BoolVar(&guiEnabled, "g", false, "Run gui client")
	flag.Parse()

	//XXX Get config dir from params
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "./testdata/gpg-datadir",
		NymsConfDir: "./testdata/nyms-datadir",
	})
}

func main() {
	switch true {
	case pipe:
		pp := pipes.CreatePipePair(os.Stdin, os.Stdout)
		defer pp.Close()
		log.Println("Listening on Stdin ...")
		for {
			go pipes.Serve(pp)
		}
	case daemonEnabled:
		log.Println("Listening on /tmp/nyms.sock ...")
		l, err := net.Listen("unix", "/tmp/nyms.sock")
		if err != nil {
			log.Fatal(err)
			return
		}

		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatal(err)
				continue
			}
			go pipes.Serve(conn)
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

}
