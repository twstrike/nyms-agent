package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/openpgp"

	gl "github.com/op/go-logging"
	"github.com/twstrike/nyms-agent/hkps"
	"github.com/twstrike/nyms-agent/keymgr"
)

var logger = gl.MustGetLogger("nymsd")

type Protocol int
type VoidArg struct{}

var void = &VoidArg{}

//
// Protocol.Version
//
const protocolVersion = 1

func (*Protocol) Version(_ VoidArg, result *int) error {
	logger.Info("Processing Version")
	*result = protocolVersion
	return nil
}

//
// Protocol.GetKeyRing
//

type GetKeyRingResult struct {
	Keys []GetKeyInfoResult
}

func (*Protocol) GetPublicKeyRing(_ VoidArg, result *GetKeyRingResult) error {
	logger.Info("Processing GetPublicKeyRing")
	if kr := keymgr.KeySource().GetPublicKeyRing(); kr != nil {
		result.Keys = make([]GetKeyInfoResult, len(kr))
		for k := range kr {
			populateKeyInfo(kr[k], &result.Keys[k])
		}
	}
	return nil
}

func (*Protocol) GetSecretKeyRing(_ VoidArg, result *GetKeyRingResult) error {
	logger.Info("Processing GetPublicKeyRing")
	if kr := keymgr.KeySource().GetSecretKeyRing(); kr != nil {
		result.Keys = make([]GetKeyInfoResult, len(kr))
		for k := range kr {
			populateKeyInfo(kr[k], &result.Keys[k])
		}
	}
	return nil
}

//
// Protocol.GetKeyInfo
//

type GetKeyInfoArgs struct {
	Address string
	KeyId   string
	Lookup  bool
}

type GetKeyInfoResult struct {
	HasKey        bool
	HasSecretKey  bool
	IsEncrypted   bool
	Fingerprint   string
	KeyId         string
	Summary       string
	UserIDs       []string
	UserImage     string
	KeyData       string
	SecretKeyData string
}

func (*Protocol) GetKeyInfo(args GetKeyInfoArgs, result *GetKeyInfoResult) error {
	logger.Info("Processing GetKeyInfo")
	if k := handleGetKeyInfo(args.Address, args.KeyId); k != nil {
		populateKeyInfo(k, result)
	}
	return nil
}

func handleGetKeyInfo(address string, keyid string) *openpgp.Entity {
	if address != "" {
		return getEntityByEmail(address)
	} else if keyid != "" {
		return getEntityByKeyId(keyid)
	}
	return nil
}

func getEntityByEmail(email string) *openpgp.Entity {
	if k, _ := keymgr.KeySource().GetSecretKey(email); k != nil {
		return k
	}
	k, _ := keymgr.KeySource().GetPublicKey(email)
	return k
}

//XXX Why no error?
func getEntityByKeyId(keyId string) *openpgp.Entity {
	id, err := decodeKeyId(keyId)
	if err != nil {
		logger.Warning(fmt.Sprint("Error decoding received key id: ", err))
		return nil
	}
	if k := keymgr.KeySource().GetSecretKeyById(id); k != nil {
		return k
	}
	return keymgr.KeySource().GetPublicKeyById(id)
}

//
// Protocol.ProcessIncoming
//

type ProcessIncomingArgs struct {
	EmailBody  string
	Passphrase string
}

type ProcessIncomingResult struct {
	VerifyResult    int
	DecryptResult   int
	EmailBody       string
	FailureMessage  string
	EncryptedKeyIds []string
	SignerKeyId     string
}

func (*Protocol) ProcessIncoming(args ProcessIncomingArgs, result *ProcessIncomingResult) (e error) {
	logger.Info("Processing ProcessIncoming")
	defer catchPanic(&e, "ProcessIncoming")
	if args.Passphrase == "" {
		return processIncomingMail(args.EmailBody, result, nil)
	} else {
		return processIncomingMail(args.EmailBody, result, []byte(args.Passphrase))
	}
}

//
// Protocol.ProcessOutgoing
//

type ProcessOutgoingArgs struct {
	Sign       bool
	Encrypt    bool
	EmailBody  string
	Passphrase string
}

type ProcessOutgoingResult struct {
	ResultCode          int
	EmailBody           string
	FailureMessage      string
	MissingKeyAddresses []string
}

func (*Protocol) ProcessOutgoing(args ProcessOutgoingArgs, result *ProcessOutgoingResult) error {
	logger.Info("Processing ProcessOutgoing")
	err := processOutgoingMail(args.EmailBody, args.Sign, args.Encrypt, args.Passphrase, result)
	if err != nil {
		return err
	}
	//result.EmailBody = body
	return nil
}

//
// Protocol.UnlockPrivateKey
//

type UnlockPrivateKeyArgs struct {
	KeyId      string
	Passphrase string
}

func (*Protocol) UnlockPrivateKey(args UnlockPrivateKeyArgs, result *bool) error {
	logger.Info("Processing.UnlockPrivateKey")
	id, err := decodeKeyId(args.KeyId)
	if err != nil {
		return err
	}
	k := keymgr.KeySource().GetSecretKeyById(id)
	if k == nil {
		return errors.New("No key found for given KeyId")
	}
	ok, err := keymgr.UnlockPrivateKey(k, []byte(args.Passphrase))
	if err != nil {
		return err
	}
	*result = ok
	return nil
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

//
// Protocol.GenerateKeys
//
type GenerateKeysArgs struct {
	RealName string
	Email    string
	Comment  string
}

func (*Protocol) GenerateKeys(args GenerateKeysArgs, result *GetKeyInfoResult) error {
	logger.Info("Processing GenerateKeys")
	e, err := keymgr.GenerateNewKey(args.RealName, args.Comment, args.Email)
	if err != nil {
		return err
	}
	populateKeyInfo(e, result)
	return nil
}

func catchPanic(err *error, fname string) {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("PANIC! caught from function %s : %s", fname, r)
		logger.Warning(msg)
		if *err == nil {
			*err = errors.New(msg)
		}
	}
}

//
//Protocol.PublishToKeyserver
//
type PublishToKeyserverArgs struct {
	Fingerprint string
	LongKeyId   string
	ShortKeyId  string

	KeyServer string
}

type PublishToKeyserverResult struct {
}

func (*Protocol) PublishToKeyserver(args PublishToKeyserverArgs, result *PublishToKeyserverResult) error {
	//defer catchPanic(&e, "PublishToKeyserver")

	//XXX Should we allow filtering which Identities and Subkeys to publish?
	key := getEntityByKeyId(args.LongKeyId)
	if key == nil {
		return fmt.Errorf("nyms-agent: could not find an entity for %s", args.LongKeyId)
	}

	ks, err := hkps.NewClient(args.KeyServer)
	if err != nil {
		return err
	}

	return ks.Submit(key)
}
