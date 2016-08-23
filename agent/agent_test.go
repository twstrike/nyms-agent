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

	b := new(bytes.Buffer)
	_, err = b.ReadFrom(m.UnverifiedBody)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if m.IsSigned {
		t.Errorf("message should not be signed")
	}
}

