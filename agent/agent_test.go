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
