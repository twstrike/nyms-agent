package keymgr

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"

	gl "github.com/op/go-logging"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var logger = gl.MustGetLogger("keymgr")

var nymsDirectory = ""

//XXX Should this implement openpgp.KeyRing rather than specialized functions?
type KeySource interface {
	GetPublicKeyRing() openpgp.EntityList
	GetPublicKey(address string) (*openpgp.Entity, error)
	GetAllPublicKeys(address string) (openpgp.EntityList, error)
	GetPublicKeyById(keyid uint64) *openpgp.Entity

	GetSecretKey(address string) (*openpgp.Entity, error)
	GetAllSecretKeys(address string) (openpgp.EntityList, error)
	GetSecretKeyById(keyid uint64) *openpgp.Entity
	GetSecretKeyRing() openpgp.EntityList
}

type KeyManager interface {
	AddPrivate(*openpgp.Entity) error
	AddPublic(*openpgp.Entity) error
	AddAll(openpgp.EntityList) error

	//Remove(*openpgp.Entity) error
	//Update(*openpgp.Entity) error
}

var defaultKeys, internalKeys *keyStore

type Conf struct {
	GPGConfDir     string
	NymsConfDir    string
	UnlockDuration int
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
func Load(conf *Conf) {
	var err error

	if conf == nil {
		if currentConf == nil {
			conf, err = defaultConf()
			if err != nil {
				panic(err)
			}
		} else {
			conf = currentConf
		}
	}

	defaultKeys, err = loadKeySourceAt(conf.GPGConfDir)
	if err != nil {
		logger.Warningf("failed to load keys from GPG dir: %v", err)
	}

	internalKeys, err = loadKeySourceAt(conf.NymsConfDir)
	if err != nil {
		//XXX Is there any unrecoverable error here?
		logger.Warningf("failed to load keys from nyms dir: %v", err)
	}

	locker.KeySource = &combinedKeySource{[]KeySource{
		internalKeys, defaultKeys,
	}}

	currentConf = conf
}

func UseAndRestore(c *Conf) func() {
	previous := currentConf
	Load(c)
	return func() { Load(previous) }
}

func loadKeySourceAt(rootPath string) (*keyStore, error) {
	s := &keyStore{
		rootPath: rootPath,
	}

	return s, s.load()
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

func GetKeyManager() KeyManager {
	return internalKeys
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

	//XXX This should not be part of serialization. That's why it's explicitly
	//called here.
	err = e.SelfSignIdentities(config)
	if err != nil {
		return nil, err
	}

	err = e.DirectSignSubkeys(config)
	if err != nil {
		return nil, err
	}

	if passphrase != nil && len(passphrase) != 0 {
		encryptPrivateKey(e, passphrase)
	}

	return e, internalKeys.AddPrivate(e)
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
