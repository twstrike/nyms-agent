package keymgr

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func TestLocalKeyring(t *testing.T) {
	localKeyRing, _ := loadKeyringAt("../testdata/gpg-datadir")
	_, err := localKeyRing.GetSecretKey("agent@nyms.io")
	if err != nil {
		t.Error("error looking up key")
	}
}

func TestUnlockPrivateWithWrongPassword(t *testing.T) {
	k := getLockedKey()
	ok, _ := UnlockPrivateKey(k, []byte("wrong"))
	if ok {
		t.Error("Unlocking private key with incorrect passphrase did not fail as expected")
	}
}

func TestUnlockPrivate(t *testing.T) {
	k := getLockedKey()
	ok, err := UnlockPrivateKey(k, []byte("password"))
	if !ok || err != nil {
		t.Error("Unlocking private key failed")
	}
}

func getLockedKey() *openpgp.Entity {
	keys := testKeySource()
	ks, _ := keys.GetAllSecretKeys("user4@example.com")
	if len(ks) != 1 {
		panic(fmt.Sprintf("expecting exactly 1 key for user4@example.com, got %d", len(ks)))
	}
	return ks[0]
}
