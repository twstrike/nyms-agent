package keymgr

import (
	"encoding/hex"

	"testing"
)

func TestInternalKeyring(t *testing.T) {
	internalKeys, _ := loadKeyringAt("../testdata/nyms-datadir")

	_, err := internalKeys.GetSecretKey("agent@nyms.io")
	if err != nil {
		t.Error("error looking up key")
	}
}

func TestGenerateKey(t *testing.T) {
	nymsDirectory = "../testdata/tmp"
	e, err := generateNewKey("foo", "", "foo@bar.com", openpgpTestConfig(), []byte("pass"))
	if err != nil {
		t.Errorf("error generating key %v", err)
	}
	const expectedGeneratedFingerprint = "3628b49589e943178a234bc2c767296788193422"
	fp := hex.EncodeToString(e.PrimaryKey.Fingerprint[:])
	if fp != expectedGeneratedFingerprint {
		t.Error("Generated key does not have expected fingerprint")
	}
	err = e.PrivateKey.Decrypt([]byte("pass"))
	if err != nil {
		t.Errorf("error decrypting key %v", err)
	}
}

func TestForget(t *testing.T) {
	internalKeys, err := loadKeyringAt("../testdata/nyms-datadir")
	if err != nil {
		t.Errorf("error load key %s", err)
	}
	e, err := internalKeys.GetSecretKey("agent@nyms.io")
	if e == nil {
		t.Errorf("error looking up key %s", err)
	}
	err = internalKeys.ForgetSecretKey(e)
	if err != nil {
		t.Errorf("error forget key pointer %p", e)
		t.Errorf("error forget key %v", err)
	}
	_, err = internalKeys.GetSecretKey("agent@nyms.io")
	if err == nil {
		t.Errorf("error forget key still found key entity")
	}
}
