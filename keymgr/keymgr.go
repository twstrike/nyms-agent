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

	defaultKeys, err = loadKeySourceAt(conf.GPGConfDir)
	if err != nil {
		return
	}

	internalKeys, err = loadKeySourceAt(conf.NymsConfDir)
	if err != nil {
		return
	}

	locker.KeySource = GetKeySource()

	currentConf = conf
	return
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

func GetKeySource() KeySource {
	return &combinedKeySource{[]KeySource{
		internalKeys, defaultKeys,
	}}
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

	if passphrase != nil && len(passphrase) != 0 {
		err = e.PrivateKey.Encrypt(passphrase)
		if err != nil {
			return nil, err
		}
	}

	internalKeys.AddPrivate(e)
	return e, nil
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
