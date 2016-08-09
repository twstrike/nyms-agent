package keymgr

import (
	"path/filepath"

	"github.com/twstrike/pgpmail"
)

var internalKeys pgpmail.KeySource

func init() {
	internalKeys, _ = loadInternalKeys()
}

func loadInternalKeys() (pgpmail.KeySource, error) {
	pubpath := filepath.Join(nymsDirectory, publicKeyringFilename)
	pubEntities, err := loadKeyringFile(pubpath)
	if err != nil {
		return nil, err
	}

	secpath := filepath.Join(nymsDirectory, secretKeyringFilename)
	secEntities, err := loadKeyringFile(secpath)
	if err != nil {
		return nil, err
	}

	return &keyStore{
		publicKeys: pubEntities,
		secretKeys: secEntities,
	}, nil
}
