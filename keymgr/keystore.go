package keymgr

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/openpgp"
)

type keyStore struct {
	rootPath string

	publicKeys openpgp.EntityList //XXX Why not openpgp.KeyRing?
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

func removeEntity(from openpgp.EntityList, e *openpgp.Entity) (openpgp.EntityList, bool) {
	for i := range from {
		if bytes.Equal(from[i].PrimaryKey.Fingerprint[:], e.PrimaryKey.Fingerprint[:]) {
			return append(from[:i], from[i+1:]...), true
		}
	}

	return from, false
}

// ForgetSecretKey forgets a secretkey by removing it from the secretKeys EntityList
func (store *keyStore) ForgetPrivateKey(entity *openpgp.Entity) error {
	var ok bool
	store.secretKeys, ok = removeEntity(store.secretKeys, entity)
	if !ok {
		return errors.New("secretkey to be forgotten not found")
	}

	return nil
}

// ForgetPublicKey forgets a publickey by removing it from the publicKeys EntityList
func (store *keyStore) ForgetPublicKey(entity *openpgp.Entity) error {
	var ok bool
	store.publicKeys, ok = removeEntity(store.publicKeys, entity)
	if !ok {
		return errors.New("publickey to be forgotten not found")
	}

	return nil
}

func (store *keyStore) lookupPublicKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.publicKeys)
}

func (store *keyStore) lookupSecretKey(email string) openpgp.EntityList {
	return lookupByEmail(email, store.secretKeys)
}

func lookupByEmail(email string, keys openpgp.EntityList) openpgp.EntityList {
	result := openpgp.EntityList{}
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

//The entitie's Itentities must be self-signed and the subkeys must have a
//direct key signature.
func (store *keyStore) AddPrivate(e *openpgp.Entity) error {
	err := store.addPublicKey(e)
	if err != nil {
		return err
	}

	err = store.addPrivateKey(e)
	if err != nil {
		return err
	}

	return store.load()
}

func (store *keyStore) AddPublic(e *openpgp.Entity) error {
	err := store.addPublicKey(e)
	if err != nil {
		return err
	}

	return store.load()
}

func (store *keyStore) RemovePrivate(e *openpgp.Entity) error {
	err := store.forgetPrivateAndSerialize(e)
	if err != nil {
		return err
	}

	//XXX Is it really a good idea to remove both public and private keys when
	//asked to remove private?
	err = store.RemovePublic(e)
	if err != nil {
		return err
	}

	return store.load()
}

func (store *keyStore) forgetPublicAndSerialize(e *openpgp.Entity) error {
	err := store.ForgetPublicKey(e)
	if err != nil {
		return err
	}

	return store.storePublicEntities()
}

func (store *keyStore) storePublicEntities() error {
	path := filepath.Join(store.rootPath, pubring)
	return serializeAndOverwrite(path, func(w io.Writer) error {
		for _, e := range store.publicKeys {
			if err := e.Serialize(w); err != nil {
				return err
			}
		}

		return nil
	})
}

func (store *keyStore) forgetPrivateAndSerialize(e *openpgp.Entity) error {
	err := store.ForgetPrivateKey(e)
	if err != nil {
		return err
	}

	return store.storePrivateEntities()
}

func (store *keyStore) storePrivateEntities() error {
	path := filepath.Join(store.rootPath, secring)
	return serializeAndOverwrite(path, func(w io.Writer) error {
		for _, e := range store.secretKeys {
			if err := e.SerializePrivateWithoutSign(w); err != nil {
				return err
			}
		}

		return nil
	})
}

func (store *keyStore) RemovePublic(e *openpgp.Entity) error {
	err := store.forgetPublicAndSerialize(e)
	if err != nil {
		return err
	}

	return store.load()
}

const (
	pubring = "pubring.gpg"
	secring = "secring.gpg"
)

func (store *keyStore) load() (err error) {
	store.secretKeys, store.publicKeys, err = loadKeyringAt(store.rootPath)
	return err
}

func serializeAndOverwrite(path string, writeKey func(io.Writer) error) error {
	lock := &sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()

	flags := os.O_WRONLY | os.O_TRUNC | os.O_CREATE
	f, err := os.OpenFile(path, flags, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	return writeKey(f)
}

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

func (store *keyStore) addPrivateKey(e *openpgp.Entity) error {
	//XXX make sure the entity is not already here
	//XXX this is not thread safe
	store.secretKeys = append(store.secretKeys, e)

	return store.storePrivateEntities()
}

func (store *keyStore) addPublicKey(e *openpgp.Entity) error {
	//XXX make sure the entity is not already here
	//XXX this is not thread safe
	store.publicKeys = append(store.publicKeys, e)

	return store.storePublicEntities()
}
