package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/twstrike/nyms-agent/protocol/types"
)

func main() {
	conn, err := net.Dial("unix", "/var/run/nyms/nyms.socket")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer conn.Close()

	c := jsonrpc.NewClient(conn)
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
	err := c.Call("Protocol.Version", types.VoidArg{}, &version)
	if err != nil {
		log.Fatal("Version error:", err)
	}
	fmt.Println("version:", version)
}

func getPublicKeyRing(c *rpc.Client) {
	var pubKeyRing types.GetKeyRingResult
	err := c.Call("Protocol.GetPublicKeyRing", types.VoidArg{}, &pubKeyRing)
	if err != nil {
		log.Fatal("GetPublicKeyRing error:", err)
	}
	fmt.Printf("pubKeyRing: %v\n", pubKeyRing.Keys)
}

func getSecretKeyRing(c *rpc.Client) {
	var secKeyRing types.GetKeyRingResult
	err := c.Call("Protocol.GetSecretKeyRing", types.VoidArg{}, &secKeyRing)
	if err != nil {
		log.Fatal("GetSecretKeyRing error:", err)
	}
	fmt.Printf("secKeyRing: %v\n", secKeyRing.Keys)
}

func updateKeyExpiration(c *rpc.Client) {
	var updateExpirationForArgs = types.UpdateExpirationForArgs{
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
	publishReturn := &types.PublishToKeyserverResult{}
	err := c.Call("Protocol.PublishToKeyserver", types.PublishToKeyserverArgs{
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
	lookupReturn := &types.KeyserverLookupResult{}
	err := c.Call("Protocol.KeyserverLookup", types.KeyServerSearchArgs{
		Search:    "nyms",
		KeyServer: "hkp://localhost:11371",
	}, lookupReturn)

	if err != nil {
		log.Fatal("KeyserverLookup error:", err)
	}

	fmt.Printf("lookupResult: %#v\n", lookupReturn)
}

func generateKeys(c *rpc.Client) types.GetKeyInfoResult {
	var generatedKey types.GetKeyInfoResult
	err := c.Call("Protocol.GenerateKeys", types.GenerateKeysArgs{
		"Nyms IO", "nyms-agent@nyms.io", "", "pass",
	}, &generatedKey)
	if err != nil {
		log.Fatal("GenerateKeys error:", err)
	}
	fmt.Printf("generatedKey: %v\n", generatedKey.KeyId)
	return generatedKey
}

func getKeyInfoByKeyId(c *rpc.Client, keyId string) types.GetKeyInfoResult {
	var gotKey types.GetKeyInfoResult
	err := c.Call("Protocol.GetKeyInfo", types.GetKeyInfoArgs{
		"", keyId, true,
	}, &gotKey)
	if err != nil {
		log.Fatal("GetKeyInfo error:", err)
	}
	fmt.Printf("gotKey: %v\n", gotKey.KeyId)
	return gotKey
}

func unlock(c *rpc.Client, keyId string) {
	var unlockReturn bool
	err := c.Call("Protocol.UnlockPrivateKey", types.UnlockPrivateKeyArgs{
		KeyId: keyId,
	}, &unlockReturn)
	if err != nil {
		log.Fatal("UnlockPrivateKey error:", err)
	}
	fmt.Printf("unlockResult: %#v\n", unlockReturn)
}
