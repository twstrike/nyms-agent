package keymgr

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/twstrike/pgpmail"

	"golang.org/x/crypto/openpgp"
)

const pubring = "pubring.gpg"
const secring = "secring.gpg"

func loadDefaultKeyringAt(rootPath string) (pgpmail.KeySource, error) {
	pubpath := filepath.Join(rootPath, pubring)
	secpath := filepath.Join(rootPath, secring)
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
