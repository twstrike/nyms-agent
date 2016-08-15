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

	var updateExpirationForArgs = protocol.UpdateExpirationForArgs{
		KeyId:        "97372B211CADF401",
		Expiratation: 1000000,
	}
	var succeed bool
	err = c.Call("Protocol.UpdateExpirationFor", updateExpirationForArgs, &succeed)
	if err != nil {
		log.Fatal("UpdateExpirationFor error: ", err)
	}
	fmt.Printf("\n expiration: %v\n", succeed)

	publishReturn := &protocol.PublishToKeyserverResult{}
	err = c.Call("Protocol.PublishToKeyserver", protocol.PublishToKeyserverArgs{
		//ShortKeyId: "1CADF401",
		LongKeyId: "97372B211CADF401",
		//Fingerprint: "579EBCB26C9772CDB7A896F297372B211CADF401",
		KeyServer: "hkp://localhost:11371",
	}, publishReturn)

	if err != nil {
		log.Fatal("PublishToKeyserver error:", err)
	}

	fmt.Printf("publishResult: %v\n", publishReturn)

	lookupReturn := &protocol.KeyserverLookupResult{}
	err = c.Call("Protocol.KeyserverLookup", protocol.KeyserverLookupArgs{
		Search:    "nyms",
		KeyServer: "hkp://localhost:11371",
	}, lookupReturn)

	if err != nil {
		log.Fatal("KeyserverLookup error:", err)
	}

	fmt.Printf("lookupResult: %#v\n", lookupReturn)
}
