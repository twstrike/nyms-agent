package agent

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/twstrike/nyms-agent/keymgr"
)

// echo "hello world" | gpg --encrypt -r 1CADF401 -a -
var encryptedData = `
-----BEGIN PGP MESSAGE-----

hQIMA5P2Afh9+6UhAQ/+JSxJqKc1isUYt7Yrwia+ZyGLSjKNJl8hUpiYclAZbkZb
iWBPUI9S/oj0ZuhPeU9cJGZL5xlHDxDUZjL11XlVslyrnj8IAovypXS/o1jD//cu
jB4NCEY1UK6yRvsui3DZ2Qp5MF2pHFF1dMs0JLD8kCmyyZUMI++FiJvIoEKb0oxk
CbeXDk4kMpVVGscFHITdOwTr2khHv2QK+HpPreZzFbNNPZLZZbYX/CkW9026PJfe
EciCTOE96hyiy6E/TlZZw75Fogc5GUEPNLvd2kqBTvcdU1hLA2m4Bpqc8rXBx10B
z8sNpxfNC60WI/mCFVQdScjX0UgbN9r52KuwIqv4klV0IHCXcn+Via1eC5CvOPHf
sFXsz8/L9fZs2OgVu1EObMJAUXWkcmiTMTmhWJdgIyWBIeRVcA+B2a1lUmh/xwDc
f4eciZkAnnTNU3IzCeHZ8VC1wvfKTRIh4CYg8R9GEzdXdjHUBw/KntLpsFEANEIx
Yl8jvijvXyz0J+OKUrrwuA4KTWFIFxPHCMnsdV1WigovnJ9dvnCPa5MvUyduE+6J
UXsluv2ScR0fVT1VSTAL0nWQ5YIrlL3Zf0NNaeypznp0h83UOt1ln8RKzgVTxHoj
ZQZ05yxUl6NMeeNgIIC0QcrWRQ8b48ce4SmanB8HiZbjF46ZOhBE7V4R0ji+kB7S
RwHPVuC+hrTqxehbzXu7Z/nFrCwJLO0lpmQ6yXisrk6qqKHx4Wyf0UoyOYqmH0nF
S/sGL6tW+ESIP0ImWtsM3FX+GTgQgP7L
=y3jo
-----END PGP MESSAGE-----
`

// echo "hello world" | gpg --sign -u A2155668 -a -
var compressedSignedData = `
-----BEGIN PGP MESSAGE-----

owEBQgK9/ZANAwAKAWfPEaWiFVZoAcsSYgBXvejPaGVsbG8gd29ybGQKiQIcBAAB
CgAGBQJXvejPAAoJEGfPEaWiFVZo8iQQAIYqXQsRPgTlkopIKQR8SL1DVVesKBzb
1U9Rt0KOKvOGN/5Q9eqFOFc7DD6K1NChbFodH8+3s/hGtIefwXVdcxI0mMNcenzC
xZq4+botL9W57Mb0iIPFa0KUgNYoDjYQ9QOvlt7eGOhaxDFfi+CcUVVqreCgLFyk
vwSWy0eMgKu/ASKJ/pj2v5EA97QVxDmbfuCXwGJWATpqcb+z7nszkHBMYGJV4RaA
JsOceXg6IPqvOj7pyuPzxK+uMC6Z6p1btJoLVnd6IyR6uCBljJXoqWkWPXm0XZ4h
XeMdHyWYjgRU8n3zl6JXOVGR4qW1Bqg/GC0wdYvrOgOgvDWYVZKPtReIbP8Ta1AQ
82QHsYGw3IoJl2/hqnLUeo2stsNa3oLU3ycEIzlM+N/Zsf/SdpMRpXkfZwVZjcpy
Oxmj/p9iuPNYZJ6Trl7stNh5rv6gE4gLU+cV+X51JjZ+bDJQSW8wby6A1xWnBIXg
Dw4exvqTNE0Z3tj4iPGFb6TJu9aK+V3vUdj73E3b4vrD3f17x3Ed+mDXMVkUR9dH
w9vP0Lan3T+f130KilhB1CY8iEYFOIsvsqI/TCrd6VcHUG9HO8st0DW60zdTluDe
8mPdZQS1xzVVWGNNhGZd1TF0dX4jgx3LqkWMKOosOBDTQiT39Z1Xa0QndaXdb3Jz
UUVZPZ7tqs3E
=BHMB
-----END PGP MESSAGE-----
`

// echo "hello world" | gpg --sign -u A2155668 -z 0 -a -
var signedData = `
-----BEGIN PGP MESSAGE-----

kA0DAAoBZ88RpaIVVmgByxJiAFe95b1oZWxsbyB3b3JsZAqJAhwEAAEKAAYFAle9
5b0ACgkQZ88RpaIVVmjiqQ//eG+9VPmWLmDgD5z4RJxMQTVMUc98y/4n4GWytNto
cn+DMGlADx8h4tLx2BKT16VR4iC/Hz4WUQVNJ8M3jinJtb/XcmMo1nwaFe8IojEi
4fmjfO6fO5ci90XUe0E8AUXtfF04bIZHr1VldHHrPM3NZBA76LwDqv3mIKsSoEnZ
wKWoVyDZpMwoQg6bNi96+DcM9WndQwDjBGoZ83zrk6LLacot+H4i5iLMpt52JskT
zQXE6rxKS4nlElt3A8TmnePNbfFIp6df7e4Xh+Ex71+SCw3aezHhd/Rbyzwf5Yq7
8m8YBb6BB+rEp7zK67VkVt14WLR7dd9HONrhWKQjBuUfKmOJPuIhK9zjlEHFMrX1
CtXoo9Rvf8VkyTIbsC4c2uYYJtixL/VvjJl6KEsmHEpxR4A0RfUIv+VbncDsfmUg
VthFBdA+t8Uay/qEVtYIuMigsMtx4nFUdm0MQ/4etR+c3nuJannQjAw9UFwqC5Yj
7xKTk8zAwiaDZsM64yqsxk0C1xzm9qZnfeQ86ctlGM2BNHjicxdGWBMXGD3AW8ai
j9jqXCjBIp25cLCYimSC9EoUevEeJaWnTtLqVDcGtxPo+o1MwBAQcpf3HnhS6F3w
An1PFTXxbQZlg6P6rFpEYSgEyrKxb7Ec/JIfQdBP0DZDkHe81IjCOV330U++sN7A
+RQ=
=Veaa
-----END PGP MESSAGE-----
`

// echo "hello world" | gpg --encrypt --sign -r 1CADF401 -u A2155668 -a -
var encryptedAndSignedData = `
-----BEGIN PGP MESSAGE-----

hQIMA5P2Afh9+6UhAQ/9HJa9wBIdB2JoVWJ38Q9Glj4GiF03HLMm0C9CjP18n9Z0
5o/6wJqhW6LCK731oEV9T2e9EU2x87UgHc+RwoQnA2ED9iaG7q/p2Qc5o/mFY6jE
HppamrOUnXKDtJC/eW/qQJObyLvFsmO+7DfXVGzhitT7/uWBcxSNb/McnKveb4Iu
W/4oiTEQ5mLkhjTJasQFSUF4ZH38c/a8p0yyshYlsdwa34Bqhe2GXhlFH0zHUxwk
HnfWssAMzlaFRxCQAQlFzBx4uGU3lqmy7xNFEAzFLG4HKsbUCoiAQJSmcdrbjV/p
Yk7bYeas9kGGdw99bTD238J6ImljfqviLL39wN3Rlt37KFLw1v2l6HRuKRpIwW8e
9ZvFBydOzifB7bOlYoPvKQpd2F7Z7/OJNpdexobOIxuG75vIIKWIG8qB4iF/TRWN
inDwuI5nP/xiNQEBvnupPo21rWnyVij1pj3JfRZP9k/849F3VrH2h0OvFFFWGTyn
KdkvfvA5r5avrdRZKNv2woxrYms8YcoZmNY5b9tiuk7MPfLQ4F5XadvEXstrkh+3
Z8/ggLTiDw9oMJEigeKHnPQVkRSTj8/9UsR3dNfFPcrKEQNWcF/sLRzLTUSUeLQZ
3MHpCSdTJrv4X5XWQ2L6E1+lP86aN6v2+QXyiHZe/ZtHbmXaSWH0avpbjgHHV+XS
6QHLtI6KaNUb9b3BrRalGZIFq/OP2JDk2yVGdC/AAcSIKo1JWljzfXOoUWnC5Twm
k5nNipQFKLz9n1KfYCgMMoAowPng3II0Asy9H8tXNgVag75LtCAoh5YcwLG7N2xn
3vZtwwsSCRWgNMx4PawSHZRTvqaKGp44oXp4qUIE6oBWOiZcJ05s0q30iyJjlfB0
wRxlKw5mWiEwPskAeOTLvR5bgIkKpIaPrCNNAG+H+DbK7sszaPCI+45jEDH3vP9Q
3PwZ0Tj4okLJYq3UhKOTy1yCbQVA1gisXtkUFpG35nD/BXVGf1276nlGJjLq2Zzq
cldYDvAT9Yq7llUFMQqSG+0ya6Bcnxys7Cmo/UqPxQJlHAXIkW0Yo0fO2CsC0RF1
oCpS52g7oL9TEMvu4uNckoFyLxGwZUYPp14GfrpSSwyTqC98XwKnzIv+iTUeISyX
+UDdnBCOsAP9OA3KBABmG2gf1aGcCndoRdcWjeri5WG1IumLGHC037Op4w8VtGSp
XkhkpSwSiqteAnli2kmoRsaFMtXde0AMftN9ZucXM+8b7vNA4344QCL9CtOAPYTE
w1W0JwhkF6i5LIut2Y0pFCTtDcX8RkvcnYwpaylrXbOnyEUM67j3Im6KpAhYhYiU
KkUMJEpKbEZamS4Eu+iytGnNxzaZBjTQPE4V1JHpSQPzeEO5g0ZxIZYHt9ImX6sS
MISEPj7ZRz4cXgyH2YEB+B4IHv3T41Mdy2a3Mciy68U5F+Hg2DpdC7Mr+5U8YyZc
6yozPLpSJQIx1ZUIlnt7oSMNAVstbeexR884vadiKDgBa8Pco8EMPTM5vd4Gol4X
Y1BI8y3j3y6KhA==
=U7wD
-----END PGP MESSAGE-----
`

func TestAgentDecryptUnsignedMessage(t *testing.T) {
	//Private key 1CADF401 is in nyms-datadir
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "../testdata/gpg-datadir",
		NymsConfDir: "../testdata/nyms-datadir",
	})

	armored := bytes.NewBufferString(encryptedData)
	block, err := armor.Decode(armored)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m, err := ReadMessage(block.Body, []byte(""))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if !m.IsEncrypted {
		t.Errorf("message should be encrypted")
	}

	if m.IsSigned {
		t.Errorf("message should NOT be signed")
	}

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	decrypted := b.String()
	if decrypted != "hello world\n" {
		t.Errorf("unexpected message: %q", string(decrypted))
	}
}

func TestAgentDecryptSignedMessage(t *testing.T) {
	//Private key 1CADF401 is in nyms-datadir
	//Public Key A2155668 is in nyms-datadir
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "../testdata/gpg-datadir",
		NymsConfDir: "../testdata/nyms-datadir",
	})

	armored := bytes.NewBufferString(encryptedAndSignedData)
	block, err := armor.Decode(armored)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m, err := ReadMessage(block.Body, []byte(""))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if !m.IsEncrypted {
		t.Errorf("message should be encrypted")
	}

	if !m.IsSigned {
		t.Errorf("message should be signed")
	}

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	decrypted := b.String()
	if decrypted != "hello world\n" {
		t.Errorf("unexpected message: %q", string(decrypted))
	}
}

func TestAgentVerifySignedMessage(t *testing.T) {
	//Public Key A2155668 is in nyms-datadir
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "../testdata/gpg-datadir",
		NymsConfDir: "../testdata/nyms-datadir",
	})

	armored := bytes.NewBufferString(compressedSignedData)
	block, err := armor.Decode(armored)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m, err := ReadMessage(block.Body, []byte(""))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if m.IsEncrypted {
		t.Errorf("message should NOT be encrypted")
	}

	if !m.IsSigned {
		t.Errorf("message should be signed")
	}

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if m.SignatureError != nil {
		t.Errorf("unexpected error: %s", m.SignatureError)
	}

	message := b.String()
	if message != "hello world\n" {
		t.Errorf("unexpected message: %q", string(message))
	}
}

func TestAgentEncryptWithoutSigning(t *testing.T) {
	//Public key 1CADF401 is in nyms-datadir
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "../testdata/gpg-datadir",
		NymsConfDir: "../testdata/nyms-datadir",
	})

	expectedMessage := "hello"
	in := bytes.NewBufferString(expectedMessage)

	//XXX Should we support both fp (579EBCB26C9772CDB7A896F297372B211CADF401)
	//and long key id (97372B211CADF401) as IDs?
	enc, err := Encrypt(in, "97372B211CADF401")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m, err := ReadMessage(enc, []byte(""))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if !m.IsEncrypted {
		t.Errorf("message should be encrypted")
	}

	if m.IsSigned {
		t.Errorf("message should not be signed")
	}

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	decrypted := b.String()
	if decrypted != expectedMessage {
		t.Errorf("unexpected message: %s", string(decrypted))
	}
}

func TestAgentEncryptWithSigning(t *testing.T) {
	//Public key 1CADF401 is in nyms-datadir
	//Private key A2155668 is in nyms-datadir
	keymgr.Load(&keymgr.Conf{
		GPGConfDir:  "../testdata/gpg-datadir",
		NymsConfDir: "../testdata/nyms-datadir",
	})

	expectedMessage := "hello"
	in := bytes.NewBufferString(expectedMessage)

	//XXX Should we support both fp (579EBCB26C9772CDB7A896F297372B211CADF401)
	//and long key id (97372B211CADF401) as IDs?
	enc, err := EncryptAndSign(in, "97372B211CADF401", "67CF11A5A2155668", []byte{})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m, err := ReadMessage(enc, []byte(""))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if !m.IsEncrypted {
		t.Errorf("message should be encrypted")
	}

	if !m.IsSigned {
		t.Errorf("message should be signed")
	}

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	decrypted := b.String()
	if decrypted != expectedMessage {
		t.Errorf("unexpected message: %s", string(decrypted))
	}
}
