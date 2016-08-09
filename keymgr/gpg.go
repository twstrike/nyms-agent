package keymgr

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"

	"github.com/twstrike/pgpmail"

	"golang.org/x/crypto/openpgp"
)

const pubring = ".gnupg/pubring.gpg"
const secring = ".gnupg/secring.gpg"

func loadDefaultKeyring() (pgpmail.KeySource, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	pubpath := filepath.Join(u.HomeDir, pubring)
	secpath := filepath.Join(u.HomeDir, secring)
	publicEntities, err := loadKeyringFile(pubpath)
	if err != nil {
		return nil, err
	}

	secretEntities, err := loadKeyringFile(secpath)
	if err != nil {
		return nil, err
	}

	return &keyStore{
		publicKeys: publicEntities,
		secretKeys: secretEntities,
	}, nil
}

func loadKeyringFile(path string) (openpgp.EntityList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	el, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return nil, err
	}
	return el, nil
}

func UnlockPrivateKey(e *openpgp.Entity, passphrase []byte) (bool, error) {
	if e.PrivateKey == nil {
		return false, errors.New("no private key")
	}
	if e.PrivateKey.Encrypted == false {
		return true, nil
	}

	err := e.PrivateKey.Decrypt(passphrase)
	if err == nil {
		decryptSubkeys(e, passphrase)
	}
	return (err == nil), nil
}

func decryptSubkeys(e *openpgp.Entity, passphrase []byte) {
	if e.Subkeys == nil {
		return
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
			sk.PrivateKey.Decrypt(passphrase)
		}
	}
}
