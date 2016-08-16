package keymgr

import "testing"

func TestLocalKeyring(t *testing.T) {
	localKeyRing, _ := loadKeySourceAt("../testdata/gpg-datadir")
	_, err := localKeyRing.GetSecretKey("agent@nyms.io")
	if err != nil {
		t.Error("error looking up key")
	}
}
