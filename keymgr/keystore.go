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

func (store *keyStore) AddPrivate(e *openpgp.Entity) error {
	defer store.load()

	//TODO use default config when we have a configuration file
	//XXX this is a lazy sign
	e.SelfSign(nil)
	err := store.addPublicKey(e)
	if err != nil {
		return err
	}

	return store.addPrivateKey(e)
}

func (store *keyStore) AddPublic(e *openpgp.Entity) error {
	defer store.load()

	return store.addPublicKey(e)
}

func (store *keyStore) RemovePrivate(e *openpgp.Entity) error {
	defer store.load()

	err := store.forgetPrivateAndSerialize(e)
	if err != nil {
		return err
	}

	//XXX Is it really a good idea to remove both public and private keys when
	//asked to remove private?
	return store.RemovePublic(e)
}

func (store *keyStore) forgetPublicAndSerialize(e *openpgp.Entity) error {
	err := store.ForgetPublicKey(e)
	if err != nil {
		return err
	}

	path := filepath.Join(store.rootPath, pubring)
	return serializeAndOverwrite(path, func(w io.Writer) error {
		for _, e := range store.publicKeys {
			err := e.Serialize(w)
			if err != nil {
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

	path := filepath.Join(store.rootPath, secring)
	return serializeAndOverwrite(path, func(w io.Writer) error {
		for _, e := range store.secretKeys {
			err := e.SerializePrivate(w, nil)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (store *keyStore) RemovePublic(e *openpgp.Entity) error {
	defer store.load()

	return store.forgetPublicAndSerialize(e)
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
	path := filepath.Join(store.rootPath, secring)
	return serializeKey(e, path, func(w io.Writer) error {
		return e.SerializePrivateWithoutSign(w)
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

	return writeKey(f)
}
