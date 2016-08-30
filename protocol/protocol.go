package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	gl "github.com/op/go-logging"
	"github.com/twstrike/nyms-agent/agent"
	"github.com/twstrike/nyms-agent/protocol/types"
	"github.com/twstrike/pgpmail"
)

func Serve(conn io.ReadWriteCloser) {
	defer conn.Close()
	protocol := new(Protocol)
	rpc.Register(protocol)
	codec := jsonrpc.NewServerCodec(conn)
	rpc.ServeCodec(codec)
}

var logger = gl.MustGetLogger("nymsd")

//XXX This should be only an adapter from jsonrcp - which requires a struct
//with exported methods, etc, etc. - to the real implementation
type Protocol int

var void = &types.VoidArg{}

//
// Protocol.Version
//
const protocolVersion = 1

func (*Protocol) Version(_ types.VoidArg, result *int) error {
	logger.Info("Processing Version")
	*result = protocolVersion
	return nil
}

//
// Protocol.GetKeyRing
//

func (*Protocol) GetPublicKeyRing(_ types.VoidArg, result *types.GetKeyRingResult) error {
	logger.Info("Processing GetPublicKeyRing")
	populateKeyRingResult(agent.GetPublicKeyRing(), result)
	return nil
}

func (*Protocol) GetSecretKeyRing(_ types.VoidArg, result *types.GetKeyRingResult) error {
	logger.Info("Processing GetPublicKeyRing")
	populateKeyRingResult(agent.GetSecretKeyRing(), result)
	return nil
}

func populateKeyRingResult(kr openpgp.EntityList, result *types.GetKeyRingResult) {
	result.Keys = make([]types.GetKeyInfoResult, len(kr))
	for k := range kr {
		populateKeyInfo(kr[k], &result.Keys[k])
	}
}

//
// Protocol.GetKeyInfo
//

func (*Protocol) GetKeyInfo(args types.GetKeyInfoArgs, result *types.GetKeyInfoResult) error {
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
	if k == nil {
		return errors.New("No Entity found")
	}

	populateKeyInfo(k, result)
	return nil
}

//
// Protocol.ProcessIncoming
//

func (*Protocol) ProcessIncoming(args types.ProcessIncomingArgs, result *types.ProcessIncomingResult) (e error) {
	logger.Info("Processing ProcessIncoming")
	defer catchPanic(&e, "ProcessIncoming")

	var m *agent.IncomingMail
	var err error

	if args.Passphrase == "" {
		m, err = agent.ProcessIncomingMail(args.EmailBody, nil)
	} else {
		m, err = agent.ProcessIncomingMail(args.EmailBody, []byte(args.Passphrase))
	}

	if err != nil {
		return err
	}

	populateIncomingResult(m, result)
	return nil
}

func populateIncomingResult(m *agent.IncomingMail, result *types.ProcessIncomingResult) {
	result.VerifyResult = pgpmail.VerifyNotSigned
	result.DecryptResult = pgpmail.DecryptNotEncrypted

	populateVerificationResult(m.VerifyStatus, result)
	populateDecriptionResult(m.DecryptionStatus, result)
	if m.DecryptionStatus.Code == pgpmail.DecryptSuccess {
		result.EmailBody = m.Message.String()
	}
}

func populateDecriptionResult(status *pgpmail.DecryptionStatus, result *types.ProcessIncomingResult) {
	result.DecryptResult = status.Code
	result.VerifyResult = status.VerifyStatus.Code

	if status.Code == pgpmail.DecryptFailed {
		result.FailureMessage = status.FailureMessage
	} else if status.VerifyStatus.Code == pgpmail.VerifyFailed {
		result.FailureMessage = status.VerifyStatus.FailureMessage
	}

	if status.Code == pgpmail.DecryptPassphraseNeeded && status.KeyIds != nil {
		for _, id := range status.KeyIds {
			result.EncryptedKeyIds = append(result.EncryptedKeyIds, encodeKeyId(id))
		}
	}
}

func populateVerificationResult(status *pgpmail.VerifyStatus, result *types.ProcessIncomingResult) {
	result.VerifyResult = status.Code
	if status.Code == pgpmail.VerifyFailed {
		result.FailureMessage = status.FailureMessage
	}

	if status.SignerKeyId != 0 {
		result.SignerKeyId = encodeKeyId(status.SignerKeyId)
	}
}

//
// Protocol.ProcessOutgoing
//

func (*Protocol) ProcessOutgoing(args types.ProcessOutgoingArgs, result *types.ProcessOutgoingResult) error {
	logger.Info("Processing ProcessOutgoing")

	s, err := agent.ProcessOutgoingMail(args.EmailBody, args.Sign, args.Encrypt, args.Passphrase)
	if err != nil {
		return err
	}

	if s != nil {
		processOutgoingStatus(s, result)
	}

	//result.EmailBody = body
	return nil
}

func processOutgoingStatus(status *pgpmail.EncryptStatus, result *types.ProcessOutgoingResult) {
	result.ResultCode = status.Code
	if status.Code == pgpmail.StatusFailed {
		result.FailureMessage = status.FailureMessage
	}

	if status.Code == pgpmail.StatusFailedNeedPubkeys {
		result.MissingKeyAddresses = status.MissingKeys
	}

	if status.Message != nil {
		result.EmailBody = status.Message.String()
	}
}

//
// Protocol.UnlockPrivateKey
//

func (*Protocol) UnlockPrivateKey(args types.UnlockPrivateKeyArgs, result *bool) error {
	logger.Info("Processing.UnlockPrivateKey")
	err := agent.UnlockPrivateKey(args.KeyId)

	*result = (err == nil)
	return err
}

//
// Protocol.GenerateKeys
//

func (*Protocol) GenerateKeys(args types.GenerateKeysArgs, result *types.GetKeyInfoResult) error {
	logger.Info("Processing GenerateKeys")
	e, err := agent.GenerateNewKey(args.RealName, args.Comment, args.Email, []byte(args.Passphrase))
	if err != nil {
		return err
	}

	populateKeyInfo(e, result)
	return nil
}

//
//Protocol.PublishToKeyserver
//
func (*Protocol) PublishToKeyserver(args types.PublishToKeyserverArgs, result *types.PublishToKeyserverResult) error {
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

//
//Protocol.UpdateExpirationFor
//

func (*Protocol) UpdateExpirationFor(args types.UpdateExpirationForArgs, result *bool) error {
	logger.Info("Processing.UpdateExpirationFor")

	ok, err := agent.UpdateExpirationFor(args.KeyId, args.Expiratation)

	*result = ok
	return err
}

//
// protocol.KeyserverLookup
//

func (*Protocol) KeyserverLookup(args types.KeyServerSearchArgs, result *types.KeyserverLookupResult) error {
	logger.Info("Processing.KeyserverLookup")

	var err error
	result.Indexes, err = agent.KeyserverLookup(args.KeyServer, args.Search)
	return err
}

func (*Protocol) KeyserverGet(args types.KeyServerSearchArgs, result *bool) error {
	logger.Info("Processing.KeyserverGet")

	err := agent.KeyserverGet(args.KeyServer, args.Search)
	if err != nil {
		return err
	}

	*result = true
	return nil
}

//
// protocol.ImportEntities
//

func (*Protocol) ImportEntities(args types.ImportEntities, result *types.VoidArg) error {
	logger.Info("Processing.ImportEntities")
	return agent.ImportArmoredEntities(bytes.NewBufferString(args.ArmoredEntities))
}

func (*Protocol) ExportEntities(args types.ExportEntities, result *types.ExportEntitiesResult) error {
	logger.Info("Processing.ExportEntities")

	dst := new(bytes.Buffer)
	defer func() {
		result.Output = dst.Bytes()
	}()

	var w io.Writer = dst
	if args.ArmoredOutput {
		armored, err := armor.Encode(dst, openpgp.PublicKeyType, nil)
		if err != nil {
			return err
		}
		defer armored.Close()

		w = armored
	}

	//XXX TODO filter keys
	return agent.ExportEntities(w, agent.GetPublicKeyRing())
}
