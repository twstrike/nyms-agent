package keymgr

import (
	"encoding/hex"

	"testing"
)

func TestGenerateDummyStore(t *testing.T) {
	nymsDirectory = "../testdata/nyms-datadir"
	internalKeys, _ := loadInternalKeys()

	_, err := internalKeys.GetSecretKey("agent@nyms.io")
	if err != nil {
		t.Error("error looking up key")
	}
}

func TestGenerateKey(t *testing.T) {
	e, err := generateNewKey("foo", "", "foo@bar.com", openpgpTestConfig())
	if err != nil {
		t.Errorf("error generating key %v", err)
	}
	const expectedGeneratedFingerprint = "3628b49589e943178a234bc2c767296788193422"
	fp := hex.EncodeToString(e.PrimaryKey.Fingerprint[:])
	if fp != expectedGeneratedFingerprint {
		t.Error("Generated key does not have expected fingerprint")
	}
}
