package agent

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/openpgp"

	"github.com/twstrike/nyms-agent/hkps"
	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/pgpmail"
)

func GetPublicKeyRing() openpgp.EntityList {
	return keymgr.KeySource().GetPublicKeyRing()
}

func GetSecretKeyRing() openpgp.EntityList {
	return keymgr.KeySource().GetSecretKeyRing()
}

func GenerateNewKey(name, comment, email string, passphrase []byte) (*openpgp.Entity, error) {
	return keymgr.GenerateNewKey(name, comment, email, passphrase)
}

func UnlockPrivateKey(keyID string, passphrase []byte) (bool, error) {
	//TODO use GetEntityByKeyId
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

type IncomingMail struct {
	*pgpmail.Message
	*pgpmail.DecryptionStatus
	*pgpmail.VerifyStatus
}

func ProcessIncomingMail(body string, passphrase []byte) (*IncomingMail, error) {
	m, err := pgpmail.ParseMessage(body)
	if err != nil {
		return nil, err
	}

	ret := &IncomingMail{
		Message: m,
	}

	if isEncrypted(m) {
		ret.DecryptionStatus = m.DecryptWith(keymgr.KeySource(), passphrase)
	}

	if isSigned(m) {
		ret.VerifyStatus = m.Verify(keymgr.KeySource())
	}

	return ret, nil
}

func ProcessOutgoingMail(body string, sign, encrypt bool, passphrase string) (*pgpmail.EncryptStatus, error) {
	//XXX Why there's only EncryptStatus and no SignStatus?

	m, err := pgpmail.ParseMessage(body)
	if err != nil {
		return nil, err
	}

	if !encrypt && !sign {
		return nil, nil
	}

	if !encrypt {
		return m.Sign(keymgr.KeySource(), passphrase), nil
	}

	if sign {
		return m.EncryptAndSign(keymgr.KeySource(), passphrase), nil
	}

	return m.Encrypt(keymgr.KeySource()), nil
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

func UpdateExpirationFor(keyId string, expirationSecs int) (bool, error) {
	//	entity, err := GetEntityByKeyId(keyId)
	//	if err != nil {
	//		return false, err
	//	}
	//
	//	selfSig := entity.PrimaryIdentity().SelfSignature
	//	selfSig.KeyLifetimeSecs = &expirationSecs
	return true, nil
}
