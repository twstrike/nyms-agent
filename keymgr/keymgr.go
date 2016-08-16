package keymgr

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sync"

	gl "github.com/op/go-logging"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const pubring = "pubring.gpg"
const secring = "secring.gpg"

var logger = gl.MustGetLogger("keymgr")

var nymsDirectory = ""

type KeySource interface {
	GetPublicKeyRing() openpgp.EntityList
	GetPublicKey(address string) (*openpgp.Entity, error)
	GetAllPublicKeys(address string) (openpgp.EntityList, error)
	GetPublicKeyById(keyid uint64) *openpgp.Entity

	GetSecretKey(address string) (*openpgp.Entity, error)
	GetAllSecretKeys(address string) (openpgp.EntityList, error)
	GetSecretKeyById(keyid uint64) *openpgp.Entity
	GetSecretKeyRing() openpgp.EntityList

	ForgetSecretKey(entity *openpgp.Entity) error
}

var defaultKeys KeySource
var internalKeys KeySource

type keyStore struct {
	publicKeys openpgp.EntityList
	secretKeys openpgp.EntityList
}

type Conf struct {
	GPGConfDir  string
	NymsConfDir string
}

var currentConf *Conf

func defaultConf() (*Conf, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	return &Conf{
		GPGConfDir:  filepath.Join(u.HomeDir, ".gnupg"),
		NymsConfDir: nymsDirectory,
	}, nil
}

//Load initializes the keyrings used by the keymanager
func Load(conf *Conf) (err error) {
	if conf == nil {
		if currentConf == nil {
			conf, err = defaultConf()
		} else {
			conf = currentConf
		}
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("conf", conf)

	defaultKeys, err = loadKeyringAt(conf.GPGConfDir)
	if err != nil {
		return
	}

	internalKeys, err = loadKeyringAt(conf.NymsConfDir)
	if err != nil {
		return
	}

	currentConf = conf
	return
}

func loadKeyringAt(rootPath string) (KeySource, error) {
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

func initNymsDir(dir string) {
	if nymsDirectory != "" {
		logger.Warning("Nyms directory already configured to %s", dir)
		return
	}

	nymsDirectory = dir
	if err := os.MkdirAll(dir, 0711); err != nil {
		logger.Fatalf("Error creating nyms directory (%s): %v", dir, err)
	}
}

func GetKeySource() KeySource {
	return &combinedKeySource{[]KeySource{
		internalKeys, defaultKeys,
	}}
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

func GenerateNewKey(name, comment, email string, passphrase []byte) (*openpgp.Entity, error) {
	return generateNewKey(name, comment, email, nil, passphrase)
}

func ArmorPublicKey(e *openpgp.Entity) (string, error) {
	return exportArmoredKey(e, openpgp.PublicKeyType, func(w io.Writer) error {
		return e.Serialize(w)
	})
}

func ArmorSecretKey(e *openpgp.Entity) (string, error) {
	return exportArmoredKey(e, openpgp.PrivateKeyType, func(w io.Writer) error {
		return e.SerializePrivate(w, nil)
	})
}

func exportArmoredKey(e *openpgp.Entity, header string, writeKey func(io.Writer) error) (string, error) {
	b := &bytes.Buffer{}
	w, err := armor.Encode(b, header, nil)
	if err != nil {
		return "", err
	}
	err = writeKey(w)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

func generateNewKey(name, comment, email string, config *packet.Config, passphrase []byte) (*openpgp.Entity, error) {
	e, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return nil, err
	}
	err = e.PrivateKey.Encrypt(passphrase)
	if err != nil {
		return nil, err
	}
	addSecretKey(e)
	return e, nil
}

func addSecretKey(e *openpgp.Entity) error {
	return serializeKey(e, secring, func(w io.Writer) error {
		return e.SerializePrivate(w, nil)
	})
}

func AddPublicKey(e *openpgp.Entity) error {
	return serializeKey(e, pubring, func(w io.Writer) error {
		return e.Serialize(w)
	})
}

func serializeKey(e *openpgp.Entity, fname string, writeKey func(io.Writer) error) error {
	lock := &sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()

	path := filepath.Join(currentConf.NymsConfDir, fname)
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

func nymsPath(fname string) string {
	return filepath.Join(nymsDirectory, fname)
}

func init() {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("Failed to get current user information: %v", err))
	}

	initNymsDir(filepath.Join(u.HomeDir, ".nyms"))
}
