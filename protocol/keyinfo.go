package protocol

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/nyms-agent/protocol/types"

	"golang.org/x/crypto/openpgp"
)

func populateKeyInfo(k *openpgp.Entity, info *types.GetKeyInfoResult) {
	info.HasKey = true
	if k.PrivateKey != nil {
		info.HasSecretKey = true
		info.IsEncrypted = k.PrivateKey.Encrypted
		if !k.PrivateKey.Encrypted {
			info.SecretKeyData, _ = keymgr.ArmorSecretKey(k)
		}
	}
	info.Fingerprint = hex.EncodeToString(k.PrimaryKey.Fingerprint[:])
	info.KeyId = encodeKeyId(k.PrimaryKey.KeyId)
	info.Summary = keymgr.RenderKey(k)

	for id, _ := range k.Identities {
		info.UserIDs = append(info.UserIDs, id)
	}

	info.KeyData, _ = keymgr.ArmorPublicKey(k)
}

func encodeKeyId(keyId uint64) string {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, keyId)
	return hex.EncodeToString(bs)
}
