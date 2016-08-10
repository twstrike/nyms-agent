package protocol

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/openpgp"

	gl "github.com/op/go-logging"
	"github.com/twstrike/nyms-agent/agent"
	"github.com/twstrike/nyms-agent/keymgr"
)

var logger = gl.MustGetLogger("nymsd")

//XXX This should be only an adapter from jsonrcp - which requires a struct
//with exported methods, etc, etc. - to the real implementation
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

	var k *openpgp.Entity
	var err error

	switch true {
	case args.Address != "":
		k, err = agent.GetEntityByEmail(args.Address)
	case args.KeyId != "":
		k, err = agent.GetEntityByKeyId(args.KeyId)
	default:
		return fmt.Errorf("Must provide either GetKeyInfoArgs.Address or GetKeyInfoArgs.KeyID")
	}

	if err != nil {
		return err
	}

	populateKeyInfo(k, result)
	return nil
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
	ok, err := agent.UnlockPrivateKey(args.KeyId, []byte(args.Passphrase))

	*result = ok
	return err
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

//
//Protocol.PublishToKeyserver
//
type PublishToKeyserverArgs struct {
	Fingerprint string
	LongKeyId   string
	ShortKeyId  string

	KeyServer string
}

type PublishToKeyserverResult struct{}

func (*Protocol) PublishToKeyserver(args PublishToKeyserverArgs, result *PublishToKeyserverResult) error {
	logger.Info("Processing PublishToKeyserver")
	//defer catchPanic(&e, "PublishToKeyserver")
	return agent.PublishToKeyserver(args.LongKeyId, args.KeyServer)
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
