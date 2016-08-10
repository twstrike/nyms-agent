package agent

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/openpgp"

	"github.com/twstrike/nyms-agent/hkps"
	"github.com/twstrike/nyms-agent/keymgr"
)

func UnlockPrivateKey(keyID string, passphrase []byte) (bool, error) {
	id, err := decodeKeyId(keyID)
	if err != nil {
		return false, err
	}

	k := keymgr.KeySource().GetSecretKeyById(id)
	if k == nil {
		return false, errors.New("No key found for given KeyId")
	}

	//XXX Why not returning an error if it failed to unlock?
	return keymgr.UnlockPrivateKey(k, passphrase)
}

func PublishToKeyserver(longKeyID, serverAddress string) error {
	//XXX Should we allow filtering which Identities and Subkeys to publish?
	key, err := GetEntityByKeyId(longKeyID)
	if err != nil {
		return err
	}

	ks, err := hkps.NewClient(serverAddress)
	if err != nil {
		return err
	}

	return ks.Submit(key)
}

func GetEntityByEmail(email string) (*openpgp.Entity, error) {
	if k, err := keymgr.KeySource().GetSecretKey(email); k != nil {
		return k, err
	}

	return keymgr.KeySource().GetPublicKey(email)
}

func GetEntityByKeyId(keyId string) (*openpgp.Entity, error) {
	id, err := decodeKeyId(keyId)
	if err != nil {
		return nil, fmt.Errorf("Error decoding received key id: ", err)
	}

	if k := keymgr.KeySource().GetSecretKeyById(id); k != nil {
		return k, nil
	}

	return keymgr.KeySource().GetPublicKeyById(id), nil
}

//XXX This is long key ID
func decodeKeyId(keyId string) (uint64, error) {
	bs, err := hex.DecodeString(keyId)
	if err != nil {
		return 0, err
	}
	if len(bs) != 8 {
		return 0, fmt.Errorf("keyId is not 8 bytes as expected, got %d", len(bs))
	}
	return binary.BigEndian.Uint64(bs), nil
}
