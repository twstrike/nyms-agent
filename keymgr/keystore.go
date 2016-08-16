package keymgr

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/openpgp"
)

type keyStore struct {
	rootPath string

	publicKeys openpgp.EntityList
	secretKeys openpgp.EntityList
}

// GetPublicKey returns the best public key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetPublicKey(address string) (*openpgp.Entity, error) {
	el := store.lookupPublicKey(address)
	if len(el) > 0 {
		return el[0], nil
	}
	return nil, errors.New("PublicKey Not found")
}

// GetAllPublicKeys returns all the public key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetAllPublicKeys(address string) (openpgp.EntityList, error) {
	return store.lookupPublicKey(address), nil
}

// GetPublicKeyById returns the public keys with keyid
func (store *keyStore) GetPublicKeyById(keyid uint64) *openpgp.Entity {
	ks := store.publicKeys.KeysById(keyid)
	if len(ks) > 0 {
		return ks[0].Entity
	}
	return nil
}

// GetPublicKeyRing returns a list of all known public keys
func (store *keyStore) GetPublicKeyRing() openpgp.EntityList {
	return store.publicKeys
}

// GetSecretKey returns the best secret key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetSecretKey(address string) (*openpgp.Entity, error) {
	el := store.lookupSecretKey(address)
	if len(el) > 0 {
		return el[0], nil
	}
	return nil, errors.New("SecretKey Not found")
}

// GetAllSecretKeys returns all the secret key for the e-mail address
// specified or nil if no key is available
func (store *keyStore) GetAllSecretKeys(address string) (openpgp.EntityList, error) {
	return store.lookupSecretKey(address), nil
}

// GetSecretKeyById returns the secret keys with keyid
func (store *keyStore) GetSecretKeyById(keyid uint64) *openpgp.Entity {
	ks := store.secretKeys.KeysById(keyid)
	if len(ks) > 0 {
		return ks[0].Entity
	}
	return nil
}

// GetSecretKeyRing returns a list of all known private keys
func (store *keyStore) GetSecretKeyRing() openpgp.EntityList {
	return store.secretKeys
}

// ForgetSecretKey forgets a secretkey by removing it from the secretKeys EntityList
func (store *keyStore) ForgetSecretKey(entity *openpgp.Entity) error {
	for i := range store.secretKeys {
		if store.secretKeys[i] == entity {
			store.secretKeys = append(store.secretKeys[:i], store.secretKeys[i+1:]...)
			return nil
		}
	}
	return errors.New("secretkey to be forgotten not found")
}

func (store *keyStore) lookupPublicKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.publicKeys)
}

func (store *keyStore) lookupSecretKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.secretKeys)
}

func lookupByEmail(email string, keys openpgp.EntityList) openpgp.EntityList {
	result := []*openpgp.Entity{}
	if keys == nil {
		return result
	}
	for _, e := range keys {
		if entityMatchesEmail(email, e) {
			result = append(result, e)
		}
	}
	return result
}

func entityMatchesEmail(email string, e *openpgp.Entity) bool {
	for _, v := range e.Identities {
		if v.UserId.Email == email {
			return true
		}
	}
	return false
}

//XXX WHen whould we name things secret or private?
func (store *keyStore) AddPrivate(e *openpgp.Entity) error {
	defer store.load()

	err := store.addSecretKey(e)
	if err != nil {
		return err
	}

	return store.addPublicKey(e)
}

func (store *keyStore) AddPublic(e *openpgp.Entity) error {
	defer store.load()

	return store.addPublicKey(e)
}

func (store *keyStore) load() (err error) {
	store.secretKeys, store.publicKeys, err = loadKeyringAt(store.rootPath)
	return err
}

const (
	pubring = "pubring.gpg"
	secring = "secring.gpg"
)

func loadKeyringAt(rootPath string) (openpgp.EntityList, openpgp.EntityList, error) {
	pubpath := filepath.Join(rootPath, pubring)
	secpath := filepath.Join(rootPath, secring)
	publicEntities, err := loadKeyringFile(pubpath)
	if err != nil {
		return nil, nil, err
	}

	secretEntities, err := loadKeyringFile(secpath)
	if err != nil {
		return nil, nil, err
	}

	return secretEntities, publicEntities, nil
}

func (store *keyStore) addSecretKey(e *openpgp.Entity) error {
	path := filepath.Join(store.rootPath, secring)
	return serializeKey(e, path, func(w io.Writer) error {
		return e.SerializePrivate(w, nil)
	})
}

func (store *keyStore) addPublicKey(e *openpgp.Entity) error {
	path := filepath.Join(store.rootPath, pubring)
	return serializeKey(e, path, func(w io.Writer) error {
		return e.Serialize(w)
	})
}

//XXX If the entity is already in the file it will be duplicated now. (oh, life)
func serializeKey(e *openpgp.Entity, path string, writeKey func(io.Writer) error) error {
	lock := &sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()

	flags := os.O_WRONLY | os.O_APPEND | os.O_CREATE
	f, err := os.OpenFile(path, flags, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := writeKey(f); err != nil {
		return err
	}
	return nil
}
