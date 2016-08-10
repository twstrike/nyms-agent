package keymgr

import (
	"path/filepath"

	"github.com/twstrike/pgpmail"
)

func loadInternalKeyring(rootPath string) (pgpmail.KeySource, error) {
	pubpath := filepath.Join(rootPath, publicKeyringFilename)
	pubEntities, err := loadKeyringFile(pubpath)
	if err != nil {
		return nil, err
	}

	secpath := filepath.Join(rootPath, secretKeyringFilename)
	secEntities, err := loadKeyringFile(secpath)
	if err != nil {
		return nil, err
	}

	return &keyStore{
		publicKeys: pubEntities,
		secretKeys: secEntities,
	}, nil
}
