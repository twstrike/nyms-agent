package keymgr

import (
	"errors"
	"os"

	"golang.org/x/crypto/openpgp"
)

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

func encryptPrivateKey(e *openpgp.Entity, passphrase []byte) (bool, error) {
	if e.PrivateKey == nil {
		return false, errors.New("no private key")
	}
	if e.PrivateKey.Encrypted {
		return true, nil
	}

	err := e.PrivateKey.Encrypt(passphrase)
	if err == nil {
		err = encryptSubkeys(e, passphrase)
	}
	return (err == nil), nil
}

func encryptSubkeys(e *openpgp.Entity, passphrase []byte) error {
	if e.Subkeys == nil {
		return nil
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && !sk.PrivateKey.Encrypted {
			err := sk.PrivateKey.Encrypt(passphrase)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
