package keymgr

import (
	"path/filepath"

	"github.com/twstrike/pgpmail"
)

func loadInternalKeyring() (pgpmail.KeySource, error) {
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
