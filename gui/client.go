package gui

import (
	"log"
	"net"
	"net/rpc"

	"github.com/twstrike/nyms-agent/pipes"
	"github.com/twstrike/nyms-agent/protocol"
)

type client struct {
	rpc *rpc.Client
}

func (c *client) establishConn() {
	conn, err := net.Dial("unix", "/tmp/nyms.sock")
	if err != nil {
		log.Fatal(err)
	}
	c.rpc = pipes.NewClient(conn)
}

func (c *client) pubKeyRing() protocol.GetKeyRingResult {
	c.establishConn()
	var pubKeyRing protocol.GetKeyRingResult
	err := c.rpc.Call("Protocol.GetPublicKeyRing", protocol.VoidArg{}, &pubKeyRing)
	if err != nil {
		log.Fatal("GetPublicKeyRing error:", err)
	}
	return pubKeyRing
}

func (c *client) createKeyPair(name, email, comment string) protocol.GetKeyInfoResult {
	c.establishConn()
	var keyinfo protocol.GetKeyInfoResult
	err := c.rpc.Call("Protocol.GenerateKeys", protocol.GenerateKeysArgs{name, email, comment}, &keyinfo)
	if err != nil {
		log.Fatal("GenerateKeys error:", err)
	}
	return keyinfo
}
