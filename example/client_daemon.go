package main

import (
	"fmt"
	"log"
	"net"

	"github.com/twstrike/nyms-agent/pipes"
	"github.com/twstrike/nyms-agent/protocol"
)

func main() {
	conn, err := net.Dial("unix", "/tmp/nyms.sock")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer conn.Close()

	c := pipes.NewClient(conn)

	var version int
	err = c.Call("Protocol.Version", protocol.VoidArg{}, &version)
	if err != nil {
		log.Fatal("Version error:", err)
	}
	fmt.Println("version:", version)

	var pubKeyRing protocol.GetKeyRingResult
	err = c.Call("Protocol.GetPublicKeyRing", protocol.VoidArg{}, &pubKeyRing)
	if err != nil {
		log.Fatal("GetPublicKeyRing error:", err)
	}
	fmt.Printf("pubKeyRing: %v\n", pubKeyRing)
}
