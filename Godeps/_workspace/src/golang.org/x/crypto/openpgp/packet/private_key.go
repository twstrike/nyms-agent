// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/openpgp/elgamal"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/s2k"
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	PrivateKey    interface{} // An *rsa.PrivateKey or *dsa.PrivateKey.
	sha1Checksum  bool
	iv            []byte

	// s2k related
	salt      []byte
	s2kMode   uint8
	s2kConfig s2k.Config
}

func NewRSAPrivateKey(currentTime time.Time, priv *rsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewDSAPrivateKey(currentTime time.Time, priv *dsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewElGamalPrivateKey(currentTime time.Time, priv *elgamal.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewElGamalPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewECDSAPrivateKey(currentTime time.Time, priv *ecdsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}

	s2kType := buf[0]

	switch s2kType {
	case 0:
		pk.s2k = nil
		pk.Encrypted = false
	case 254, 255:
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}
		pk.cipher = CipherFunction(buf[0])
		pk.Encrypted = true
		pk.s2k, pk.s2kMode, pk.s2kConfig.Hash, pk.salt, pk.s2kConfig.S2KCount, err = s2k.Parse2(r)
		if err != nil {
			return
		}
		if s2kType == 254 {
			pk.sha1Checksum = true
		}
	default:
		return errors.UnsupportedError("deprecated s2k function in private key")
	}

	if pk.Encrypted {
		blockSize := pk.cipher.blockSize()
		if blockSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher)))
		}
		pk.iv = make([]byte, blockSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
	}

	pk.encryptedData, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	if !pk.Encrypted {
		return pk.parsePrivateKey(pk.encryptedData)
	}

	return
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer) (err error) {
	// TODO(agl): support encrypted private keys
	buf := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(buf)
	if err != nil {
		return
	}
	buf.WriteByte(0 /* no encryption */)

	privateKeyBuf := bytes.NewBuffer(nil)

	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializeRSAPrivateKey(privateKeyBuf, priv)
	case *dsa.PrivateKey:
		err = serializeDSAPrivateKey(privateKeyBuf, priv)
	case *elgamal.PrivateKey:
		err = serializeElGamalPrivateKey(privateKeyBuf, priv)
	case *ecdsa.PrivateKey:
		err = serializeECDSAPrivateKey(privateKeyBuf, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	if err != nil {
		return
	}

	ptype := packetTypePrivateKey
	contents := buf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err = serializeHeader(w, ptype, len(contents)+len(privateKeyBytes)+2)
	if err != nil {
		return
	}
	_, err = w.Write(contents)
	if err != nil {
		return
	}
	_, err = w.Write(privateKeyBytes)
	if err != nil {
		return
	}

	checksum := mod64kHash(privateKeyBytes)
	var checksumBytes [2]byte
	checksumBytes[0] = byte(checksum >> 8)
	checksumBytes[1] = byte(checksum)
	_, err = w.Write(checksumBytes[:])

	return
}

func serializeRSAPrivateKey(w io.Writer, priv *rsa.PrivateKey) error {
	err := writeBig(w, priv.D)
	if err != nil {
		return err
	}
	err = writeBig(w, priv.Primes[1])
	if err != nil {
		return err
	}
	err = writeBig(w, priv.Primes[0])
	if err != nil {
		return err
	}
	return writeBig(w, priv.Precomputed.Qinv)
}

func serializeDSAPrivateKey(w io.Writer, priv *dsa.PrivateKey) error {
	return writeBig(w, priv.X)
}

func serializeElGamalPrivateKey(w io.Writer, priv *elgamal.PrivateKey) error {
	return writeBig(w, priv.X)
}

func serializeECDSAPrivateKey(w io.Writer, priv *ecdsa.PrivateKey) error {
	return writeBig(w, priv.D)
}

func (pk *PrivateKey) Encrypt(passphrase []byte) error {
	privateKeyBuf := bytes.NewBuffer(nil)
	err := pk.SerializePGPPrivate(privateKeyBuf)
	if err != nil {
		return err
	}

	privateKeyBytes := privateKeyBuf.Bytes()
	key := make([]byte, pk.cipher.KeySize())
	pk.salt = make([]byte, 8)
	rand.Read(pk.salt)
	pk.s2kConfig.S2KCount = 65536
	pk.s2kConfig.Hash = crypto.SHA1

	pk.s2k = func(out, in []byte) {
		s2k.Iterated(out, pk.s2kConfig.Hash.New(), in, pk.salt, pk.s2kConfig.S2KCount)
	}
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	cfb := cipher.NewCFBEncrypter(block, pk.iv)

	if pk.sha1Checksum {
		h := sha1.New()
		h.Write(privateKeyBytes)
		sum := h.Sum(nil)
		privateKeyBytes = append(privateKeyBytes, sum...)
	} else {
		var sum uint16
		for i := 0; i < len(privateKeyBytes); i++ {
			sum += uint16(privateKeyBytes[i])
		}
		privateKeyBytes = append(privateKeyBytes, uint8(sum>>8))
		privateKeyBytes = append(privateKeyBytes, uint8(sum))
	}

	pk.encryptedData = make([]byte, len(privateKeyBytes))
	cfb.XORKeyStream(pk.encryptedData, privateKeyBytes)

	pk.Encrypted = true
	return err
}

func (pk *PrivateKey) SerializePGP(w io.Writer) error {
	buf := bytes.NewBuffer(nil)
	pk.PublicKey.serializeWithoutHeaders(buf)

	privateKeyBuf := bytes.NewBuffer(nil)
	encodedKeyBuf := bytes.NewBuffer(nil)
	if !pk.Encrypted {
		pk.SerializePGPPrivate(privateKeyBuf)
	} else {
		encodedKeyBuf.Write([]byte{0xfe})
		encodedKeyBuf.Write([]byte{0x03})
		encodedKeyBuf.Write([]byte{0x03})
		hashID, _ := s2k.HashToHashId(pk.s2kConfig.Hash)
		encodedKeyBuf.Write([]byte{hashID})
		encodedKeyBuf.Write(pk.salt)
		encodedKeyBuf.Write([]byte{pk.s2kConfig.EncodedCount()})

		privateKeyBuf.Write(pk.encryptedData)
	}

	ptype := packetTypePrivateKey
	contents := buf.Bytes()
	encodedKey := encodedKeyBuf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}

	err := serializeHeader(w, ptype, len(contents)+len(encodedKey)+len(pk.iv)+len(privateKeyBytes))
	w.Write(contents)
	w.Write(encodedKey)
	w.Write(pk.iv)
	w.Write(privateKeyBytes)

	return err
}

func (pk *PrivateKey) SerializePGPPrivate(privateKeyBuf io.Writer) error {
	var err error
	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializePGPRSAPrivateKey(privateKeyBuf, priv)
	case *dsa.PrivateKey:
		err = serializePGPDSAPrivateKey(privateKeyBuf, priv)
	case *elgamal.PrivateKey:
		err = serializePGPElGamalPrivateKey(privateKeyBuf, priv)
	case *ecdsa.PrivateKey:
		err = serializePGPECDSAPrivateKey(privateKeyBuf, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	return err
}

func serializePGPRSAPrivateKey(w io.Writer, priv *rsa.PrivateKey) error {
	binary.Write(w, binary.BigEndian, priv.D.BitLen())
	err := writeBig(w, priv.D)
	if err != nil {
		return err
	}
	binary.Write(w, binary.BigEndian, priv.Primes[0].BitLen())
	err = writeBig(w, priv.Primes[0])
	if err != nil {
		return err
	}
	binary.Write(w, binary.BigEndian, priv.Primes[1].BitLen())
	err = writeBig(w, priv.Primes[1])
	if err != nil {
		return err
	}
	u := new(big.Int).ModInverse(priv.Primes[0], priv.Primes[1])
	binary.Write(w, binary.BigEndian, u.BitLen())
	return writeBig(w, u)
}

func serializePGPDSAPrivateKey(w io.Writer, priv *dsa.PrivateKey) error {
	binary.Write(w, binary.BigEndian, priv.X.BitLen())
	return writeBig(w, priv.X)
}

func serializePGPElGamalPrivateKey(w io.Writer, priv *elgamal.PrivateKey) error {
	binary.Write(w, binary.BigEndian, priv.X.BitLen())
	return writeBig(w, priv.X)
}

func serializePGPECDSAPrivateKey(w io.Writer, priv *ecdsa.PrivateKey) error {
	binary.Write(w, binary.BigEndian, priv.D.BitLen())
	return writeBig(w, priv.D)
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	cfb := cipher.NewCFBDecrypter(block, pk.iv)

	data := make([]byte, len(pk.encryptedData))
	cfb.XORKeyStream(data, pk.encryptedData)

	if pk.sha1Checksum {
		if len(data) < sha1.Size {
			return errors.StructuralError("truncated private key data")
		}
		h := sha1.New()
		h.Write(data[:len(data)-sha1.Size])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-sha1.Size]
	} else {
		if len(data) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		var sum uint16
		for i := 0; i < len(data)-2; i++ {
			sum += uint16(data[i])
		}
		if data[len(data)-2] != uint8(sum>>8) ||
			data[len(data)-1] != uint8(sum) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-2]
	}

	return pk.parsePrivateKey(data)
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	switch pk.PublicKey.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSASignOnly, PubKeyAlgoRSAEncryptOnly:
		return pk.parseRSAPrivateKey(data)
	case PubKeyAlgoDSA:
		return pk.parseDSAPrivateKey(data)
	case PubKeyAlgoElGamal:
		return pk.parseElGamalPrivateKey(data)
	case PubKeyAlgoECDSA:
		return pk.parseECDSAPrivateKey(data)
	}
	panic("impossible")
}

func (pk *PrivateKey) parseRSAPrivateKey(data []byte) (err error) {
	rsaPub := pk.PublicKey.PublicKey.(*rsa.PublicKey)
	rsaPriv := new(rsa.PrivateKey)
	rsaPriv.PublicKey = *rsaPub

	buf := bytes.NewBuffer(data)
	d, _, err := readMPI(buf)
	if err != nil {
		return
	}
	p, _, err := readMPI(buf)
	if err != nil {
		return
	}
	q, _, err := readMPI(buf)
	if err != nil {
		return
	}

	rsaPriv.D = new(big.Int).SetBytes(d)
	rsaPriv.Primes = make([]*big.Int, 2)
	rsaPriv.Primes[0] = new(big.Int).SetBytes(p)
	rsaPriv.Primes[1] = new(big.Int).SetBytes(q)
	if err := rsaPriv.Validate(); err != nil {
		return err
	}
	rsaPriv.Precompute()

	pk.PrivateKey = rsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseDSAPrivateKey(data []byte) (err error) {
	dsaPub := pk.PublicKey.PublicKey.(*dsa.PublicKey)
	dsaPriv := new(dsa.PrivateKey)
	dsaPriv.PublicKey = *dsaPub

	buf := bytes.NewBuffer(data)
	x, _, err := readMPI(buf)
	if err != nil {
		return
	}

	dsaPriv.X = new(big.Int).SetBytes(x)
	pk.PrivateKey = dsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseElGamalPrivateKey(data []byte) (err error) {
	pub := pk.PublicKey.PublicKey.(*elgamal.PublicKey)
	priv := new(elgamal.PrivateKey)
	priv.PublicKey = *pub

	buf := bytes.NewBuffer(data)
	x, _, err := readMPI(buf)
	if err != nil {
		return
	}

	priv.X = new(big.Int).SetBytes(x)
	pk.PrivateKey = priv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDSAPrivateKey(data []byte) (err error) {
	ecdsaPub := pk.PublicKey.PublicKey.(*ecdsa.PublicKey)

	buf := bytes.NewBuffer(data)
	d, _, err := readMPI(buf)
	if err != nil {
		return
	}

	pk.PrivateKey = &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         new(big.Int).SetBytes(d),
	}
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}
