package main

import (
	"fmt"
	"log"
	"net"

	"github.com/twstrike/nyms-agent/pipes"
	"github.com/twstrike/nyms-agent/protocol"
)

func main() {
	conn, err := net.Dial("unix", "/tmp/nyms")
	if err != nil {
		log.Fatal(err)
	}
	c := pipes.NewClient(conn, conn, true)
	var reply int
	err = c.Call("Protocol.Version", protocol.VoidArg{}, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	fmt.Println("reply:", reply)
}
