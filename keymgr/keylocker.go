package keymgr

import (
	"bytes"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type keyLocker struct {
	KeySource
	secretKeys openpgp.EntityList
}

var locker keyLocker

func GetKeyLocker() *keyLocker {
	return &locker
}

func (l *keyLocker) UnlockSecretKeyById(keyID uint64, passphrase []byte) error {
	var k *openpgp.Entity
	ks := l.secretKeys.KeysById(keyID)
	if len(ks) > 0 {
		k = ks[0].Entity
	} else {
		src := l.KeySource.GetSecretKeyById(keyID)
		k = new(openpgp.Entity)
		copyEntity(k, src)
		l.secretKeys = append(l.secretKeys, k)
	}
	if k.PrivateKey.Encrypted {
		go l.forgetSecretKey(currentConf.UnlockDuration, k)
		err := k.PrivateKey.Decrypt(passphrase)
		if err == nil {
			err = decryptSubkeys(k, passphrase)
		}
		return err
	}
	return nil
}

func (l *keyLocker) GetSecretKeyById(keyID uint64) *openpgp.Entity {
	ks := l.secretKeys.KeysById(keyID)
	if len(ks) > 0 {
		return ks[0].Entity
	} else {
		return l.KeySource.GetSecretKeyById(keyID)
	}
}

func copyEntity(dst, src *openpgp.Entity) {
	dst.PrimaryKey = src.PrimaryKey
	dst.Identities = src.Identities
	dst.Revocations = src.Revocations

	buf := bytes.NewBuffer(nil)
	src.PrivateKey.Serialize(buf)
	privateKey, err := packet.Read(buf)
	dst.PrivateKey = privateKey.(*packet.PrivateKey)

	for _, sub := range src.Subkeys {
		sub.PrivateKey.Serialize(buf)
		subKey, err := packet.Read(buf)
		if err != nil {
			panic(err)
		}
		dst.Subkeys = append(dst.Subkeys, openpgp.Subkey{
			PrivateKey: subKey.(*packet.PrivateKey),
			PublicKey:  sub.PublicKey,
			Sig:        sub.Sig,
		})
	}

	if err != nil {
		panic(err)
	}
}

// forgetSecretKey forgets a secretkey by removing it from the secretKeys EntityList
func (l *keyLocker) forgetSecretKey(n int, entity *openpgp.Entity) {
	<-time.Tick(time.Duration(n) * time.Second)
	for i := range l.secretKeys {
		if l.secretKeys[i] == entity {
			l.secretKeys = append(l.secretKeys[:i], l.secretKeys[i+1:]...)
			return
		}
	}
	logger.Error("secretkey to be forgotten not found")
}

func decryptSubkeys(e *openpgp.Entity, passphrase []byte) error {
	if e.Subkeys == nil {
		return nil
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
			err := sk.PrivateKey.Decrypt(passphrase)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
