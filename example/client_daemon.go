package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"

	"github.com/twstrike/nyms-agent/protocol"
)

func main() {
	conn, err := net.Dial("unix", "/tmp/nyms.sock")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer conn.Close()

	c := protocol.NewClient(conn)

	getVersion(c)
	getPublicKeyRing(c)
	getSecretKeyRing(c)
	updateKeyExpiration(c)
	generatedKey := generateKeys(c)
	getPublicKeyRing(c)
	getSecretKeyRing(c)
	getKeyInfoByKeyId(c, generatedKey.KeyId)
	unlock(c, generatedKey.KeyId)

}

func getVersion(c *rpc.Client) {
	var version int
	err := c.Call("Protocol.Version", protocol.VoidArg{}, &version)
	if err != nil {
		log.Fatal("Version error:", err)
	}
	fmt.Println("version:", version)
}

func getPublicKeyRing(c *rpc.Client) {
	var pubKeyRing protocol.GetKeyRingResult
	err := c.Call("Protocol.GetPublicKeyRing", protocol.VoidArg{}, &pubKeyRing)
	if err != nil {
		log.Fatal("GetPublicKeyRing error:", err)
	}
	fmt.Printf("pubKeyRing: %v\n", pubKeyRing.Keys)
}

func getSecretKeyRing(c *rpc.Client) {
	var secKeyRing protocol.GetKeyRingResult
	err := c.Call("Protocol.GetSecretKeyRing", protocol.VoidArg{}, &secKeyRing)
	if err != nil {
		log.Fatal("GetSecretKeyRing error:", err)
	}
	fmt.Printf("secKeyRing: %v\n", secKeyRing.Keys)
}

func updateKeyExpiration(c *rpc.Client) {
	var updateExpirationForArgs = protocol.UpdateExpirationForArgs{
		KeyId:        "97372B211CADF401",
		Expiratation: 10000,
	}
	var succeed bool
	err := c.Call("Protocol.UpdateExpirationFor", updateExpirationForArgs, &succeed)
	if err != nil {
		log.Fatal("UpdateExpirationFor error: ", err)
	}

}
func publishToKeyserver(c *rpc.Client) {
	publishReturn := &protocol.PublishToKeyserverResult{}
	err := c.Call("Protocol.PublishToKeyserver", protocol.PublishToKeyserverArgs{
		//ShortKeyId: "1CADF401",
		LongKeyId: "97372B211CADF401",
		//Fingerprint: "579EBCB26C9772CDB7A896F297372B211CADF401",
		KeyServer: "hkp://localhost:11371",
	}, publishReturn)

	if err != nil {
		log.Fatal("PublishToKeyserver error:", err)
	}

	fmt.Printf("publishResult: %v\n", publishReturn)
}

func lookupPublicKey(c *rpc.Client) {
	lookupReturn := &protocol.KeyserverLookupResult{}
	err := c.Call("Protocol.KeyserverLookup", protocol.KeyserverLookupArgs{
		Search:    "nyms",
		KeyServer: "hkp://localhost:11371",
	}, lookupReturn)

	if err != nil {
		log.Fatal("KeyserverLookup error:", err)
	}

	fmt.Printf("lookupResult: %#v\n", lookupReturn)
}

func generateKeys(c *rpc.Client) protocol.GetKeyInfoResult {
	var generatedKey protocol.GetKeyInfoResult
	err := c.Call("Protocol.GenerateKeys", protocol.GenerateKeysArgs{
		"Nyms IO", "nyms-agent@nyms.io", "", "pass",
	}, &generatedKey)
	if err != nil {
		log.Fatal("GenerateKeys error:", err)
	}
	fmt.Printf("generatedKey: %v\n", generatedKey.KeyId)
	return generatedKey
}

func getKeyInfoByKeyId(c *rpc.Client, keyId string) protocol.GetKeyInfoResult {
	var gotKey protocol.GetKeyInfoResult
	err := c.Call("Protocol.GetKeyInfo", protocol.GetKeyInfoArgs{
		"", keyId, true,
	}, &gotKey)
	if err != nil {
		log.Fatal("GetKeyInfo error:", err)
	}
	fmt.Printf("gotKey: %v\n", keyId)
	return gotKey
}

func unlock(c *rpc.Client, keyId string) {
	var unlockReturn bool
	err := c.Call("Protocol.UnlockPrivateKey", protocol.UnlockPrivateKeyArgs{
		KeyId:      keyId,
		Passphrase: "pass",
	}, &unlockReturn)
	if err != nil {
		log.Fatal("UnlockPrivateKey error:", err)
	}
	fmt.Printf("unlockResult: %#v\n", unlockReturn)
}
