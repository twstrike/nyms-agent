package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/twstrike/nyms-agent/hkps"
	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/pgpmail"
)

func GetPublicKeyRing() openpgp.EntityList {
	return keymgr.GetKeySource().GetPublicKeyRing()
}

func GetSecretKeyRing() openpgp.EntityList {
	return keymgr.GetKeyLocker().GetSecretKeyRing()
}

func GenerateNewKey(name, comment, email string, passphrase []byte) (*openpgp.Entity, error) {
	return keymgr.GenerateNewKey(name, comment, email, passphrase)
}

func UnlockPrivateKey(keyID string, passphrase []byte) error {
	id, err := decodeKeyId(keyID)
	if err != nil {
		return err
	}
	return keymgr.GetKeyLocker().UnlockSecretKeyById(id, passphrase)
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

	keytext, err := keymgr.ArmorPublicKey(key)
	if err != nil {
		return err
	}

	return ks.Submit(keytext)
}

func GetEntityByEmail(email string) (*openpgp.Entity, error) {
	if k, err := keymgr.GetKeyLocker().GetSecretKey(email); k != nil {
		return k, err
	}

	return keymgr.GetKeySource().GetPublicKey(email)
}

func GetEntityByKeyId(keyId string) (*openpgp.Entity, error) {
	id, err := decodeKeyId(keyId)
	if err != nil {
		return nil, fmt.Errorf("Error decoding received key id: ", err)
	}

	if k := keymgr.GetKeyLocker().GetSecretKeyById(id); k != nil {
		return k, nil
	}

	return keymgr.GetKeySource().GetPublicKeyById(id), nil
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
		ret.DecryptionStatus = m.DecryptWith(keymgr.GetKeyLocker(), passphrase)
	}

	if isSigned(m) {
		ret.VerifyStatus = m.Verify(keymgr.GetKeySource())
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
		return m.Sign(keymgr.GetKeyLocker(), passphrase), nil
	}

	if sign {
		return m.EncryptAndSign(keymgr.GetKeyLocker(), passphrase), nil
	}

	return m.Encrypt(keymgr.GetKeySource()), nil
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

//XXX Is this done?
func UpdateExpirationFor(keyId string, expirationSecs uint32) (bool, error) {
	entity, err := GetEntityByKeyId(keyId)

	if err != nil {
		return false, err
	}

	old := primaryIdentity(entity).SelfSignature

	primaryIdentity(entity).SelfSignature = &packet.Signature{
		CreationTime:    time.Now(),
		SigType:         old.SigType,
		PubKeyAlgo:      old.PubKeyAlgo,
		Hash:            old.Hash,
		IsPrimaryId:     old.IsPrimaryId,
		FlagsValid:      true,
		FlagSign:        true,
		FlagCertify:     true,
		IssuerKeyId:     &entity.PrimaryKey.KeyId,
		KeyLifetimeSecs: &expirationSecs,
	}

	return true, nil
}

func primaryIdentity(e *openpgp.Entity) *openpgp.Identity {
	var firstIdentity *openpgp.Identity
	for _, ident := range e.Identities {
		if firstIdentity == nil {
			firstIdentity = ident
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident
		}
	}
	return firstIdentity
}

func KeyserverLookup(serverAddress, search string) ([]*hkps.Index, error) {
	ks, err := hkps.NewClient(serverAddress)
	if err != nil {
		return nil, err
	}

	return ks.Lookup(search)
}
