package keymgr

import (
	"bytes"
	"errors"
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

func (l *keyLocker) UnlockSecretKeyById(keyID uint64, passphrase []byte) (err error) {
	var k *openpgp.Entity
	ks := l.secretKeys.KeysById(keyID)
	if len(ks) > 0 {
		k = ks[0].Entity
	} else {
		src := l.KeySource.GetSecretKeyById(keyID)
		if src == nil {
			logger.Error("secretkey to be unlocked not found")
			err = errors.New("secretkey to be unlocked not found")
			return
		}
		k, err = copyEntity(src)
		if err != nil {
			return
		}
		l.secretKeys = append(l.secretKeys, k)
	}
	if k.PrivateKey.Encrypted {
		go l.forgetSecretKey(currentConf.UnlockDuration, k)
		err = k.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return
		}
		err = decryptSubkeys(k, passphrase)
		if err != nil {
			return
		}
	}
	return
}

func (l *keyLocker) GetSecretKeyById(keyID uint64) *openpgp.Entity {
	ks := l.secretKeys.KeysById(keyID)
	if len(ks) > 0 {
		return ks[0].Entity
	} else {
		return l.KeySource.GetSecretKeyById(keyID)
	}
}

func copyEntity(src *openpgp.Entity) (*openpgp.Entity, error) {
	buf := bytes.NewBuffer(nil)
	err := src.SerializePrivateWithoutSign(buf, nil)
	if err != nil {
		return nil, err
	}
	dst, err := openpgp.ReadEntity(packet.NewReader(buf))
	if err != nil {
		return nil, err
	}
	return dst, nil
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
