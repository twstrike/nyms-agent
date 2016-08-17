package keymgr

import (
	"encoding/hex"
	"os"

	"golang.org/x/crypto/openpgp"

	"testing"
)

func TestInternalKeyring(t *testing.T) {
	internalKeys, _ := loadKeySourceAt("../testdata/nyms-datadir")

	_, err := internalKeys.GetSecretKey("agent@nyms.io")
	if err != nil {
		t.Error("error looking up key")
	}
}

func TestGenerateKey(t *testing.T) {
	internalKeys, _ = loadKeySourceAt("../testdata/tmp")
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
	internalKeys, err := loadKeySourceAt("../testdata/nyms-datadir")
	if err != nil {
		t.Errorf("error load key %s", err)
	}
	e, err := internalKeys.GetSecretKey("agent@nyms.io")
	if e == nil {
		t.Errorf("error looking up key %s", err)
	}
	err = internalKeys.ForgetPrivateKey(e)
	if err != nil {
		t.Errorf("error forget key pointer %p", e)
		t.Errorf("error forget key %v", err)
	}
	_, err = internalKeys.GetSecretKey("agent@nyms.io")
	if err == nil {
		t.Errorf("error forget key still found key entity")
	}
}

func TestKeyManager(t *testing.T) {
	os.Remove("../testdata/tmp/pubring.gpg")
	os.Remove("../testdata/tmp/secring.gpg")
	manager, _ := loadKeySourceAt("../testdata/tmp")

	_, err := manager.GetSecretKey("secret@nyms.io")
	if err == nil {
		t.Errorf("entity should not exist")
	}

	_, err = manager.GetPublicKey("secret@nyms.io")
	if err == nil {
		t.Errorf("entity should not exist")
	}

	_, err = manager.GetPublicKey("public@nyms.io")
	if err == nil {
		t.Errorf("entity should not exist")
	}

	e, err := openpgp.NewEntity("name", "comment", "secret@nyms.io", nil)
	if err != nil {
		t.Errorf("error creating entity: %s", err)
	}

	err = manager.AddPrivate(e)
	if err != nil {
		t.Errorf("error adding entity: %s", err)
	}

	e, err = openpgp.NewEntity("name", "comment", "public@nyms.io", nil)
	if err != nil {
		t.Errorf("error creating entity: %s", err)
	}

	// XXX maybe SelfSign should only be used for a new Entity
	e.SelfSign(nil)
	err = manager.AddPublic(e)
	if err != nil {
		t.Errorf("error adding entity: %s", err)
	}

	_, err = manager.GetSecretKey("secret@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}

	_, err = manager.GetPublicKey("secret@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}

	_, err = manager.GetPublicKey("public@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}
}

func TestKeyManagerRemove(t *testing.T) {
	os.Remove("../testdata/tmp/pubring.gpg")
	os.Remove("../testdata/tmp/secring.gpg")
	manager, _ := loadKeySourceAt("../testdata/tmp")

	e, err := openpgp.NewEntity("name", "comment", "secret@nyms.io", nil)
	if err != nil {
		t.Errorf("error creating entity: %s", err)
	}

	err = manager.AddPrivate(e)
	if err != nil {
		t.Errorf("error adding entity: %s", err)
	}

	e, err = manager.GetSecretKey("secret@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}

	_, err = manager.GetPublicKey("secret@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}

	err = manager.RemovePrivate(e)
	if err != nil {
		t.Errorf("error removing entity: %s", err)
	}

	e, err = manager.GetSecretKey("secret@nyms.io")
	if err == nil {
		t.Errorf("entity exists: %s", e)
	}

	e, err = manager.GetPublicKey("secret@nyms.io")
	if err == nil {
		t.Errorf("entity exists: %s", e)
	}

	e, err = openpgp.NewEntity("name", "comment", "public@nyms.io", nil)
	if err != nil {
		t.Errorf("error creating entity: %s", err)
	}

	// XXX maybe SelfSign should only be used for a new Entity
	e.SelfSign(nil)
	err = manager.AddPublic(e)
	if err != nil {
		t.Errorf("error adding entity: %s", err)
	}

	_, err = manager.GetPublicKey("public@nyms.io")
	if err != nil {
		t.Errorf("entity should exist: %s", err)
	}

	err = manager.RemovePublic(e)
	if err != nil {
		t.Errorf("error removing entity: %s", err)
	}

	e, err = manager.GetPublicKey("public@nyms.io")
	if err == nil {
		t.Errorf("entity exists: %s", e)
	}
}
