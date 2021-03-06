package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/nyms-agent/pipes"
	"github.com/twstrike/nyms-agent/protocol"
)

const (
	defaultDaemonAddress = "/var/run/nyms/nyms.socket"
)

var pipe bool
var daemonEnabled bool
var guiEnabled bool

func init() {
	flag.BoolVar(&pipe, "pipe", false, "Run RPC service on stdin/stdout")
	flag.BoolVar(&daemonEnabled, "d", false, "Run RPC service on unix domain socket")
	flag.Parse()

	//XXX Get config dir from params
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:     "./testdata/gpg-datadir",
		NymsConfDir:    "./testdata/nyms-datadir",
		UnlockDuration: 5,
	})
}

func main() {
	switch true {
	case pipe:
		pp := pipes.CreatePipePair(os.Stdin, os.Stdout)
		defer pp.Close()
		log.Println("Listening on Stdin ...")
		for {
			go protocol.Serve(pp)
		}
	case daemonEnabled:
		err := os.Remove(defaultDaemonAddress)
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
			os.Exit(-1)
		}

		log.Printf("Listening on %s...", defaultDaemonAddress)
		l, err := net.Listen("unix", defaultDaemonAddress)
		if err != nil {
			log.Fatal(err)
			os.Exit(-1)
		}

		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatal(err)
				continue
			}
			go protocol.Serve(conn)
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

}
