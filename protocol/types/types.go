package types

import "github.com/twstrike/nyms-agent/hkps"

type VoidArg struct{}

type GetKeyRingResult struct {
	Keys []GetKeyInfoResult
}

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

type UnlockPrivateKeyArgs struct {
	KeyId string
}

type GenerateKeysArgs struct {
	RealName   string
	Email      string
	Comment    string
	Passphrase string
}

type PublishToKeyserverArgs struct {
	Fingerprint string
	LongKeyId   string
	ShortKeyId  string

	KeyServer string
}

type PublishToKeyserverResult struct{}

type UpdateExpirationForArgs struct {
	KeyId        string
	Expiratation uint32
}

type KeyServerSearchArgs struct {
	Search    string
	KeyServer string
}

type KeyserverLookupResult struct {
	Indexes []*hkps.Index //XXX Is there any problem if this is a pointer?
}

type ImportEntities struct {
	ArmoredEntities string
}
