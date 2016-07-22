package keymgr

import (
	"fmt"
	"strings"

	"crypto/dsa"
	"crypto/rsa"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func RenderKey(e *openpgp.Entity) string {
	lines := []string{}
	lines = append(lines, renderPublicKey(e.PrimaryKey))

	for _, v := range e.Identities {
		lines = append(lines, fmt.Sprintf("uid     %s", v.Name))
	}

	return strings.Join(lines, "\n")
}

func renderPublicKey(pk *packet.PublicKey) string {
	ktag := renderKeyTag(pk.PublicKey)
	if pk.IsSubkey {
		return fmt.Sprintf("sub   %s/%X", ktag, uint32(pk.KeyId&0xFFFFFFFF))
	} else {
		return fmt.Sprintf("pub   %s/%X", ktag, uint32(pk.KeyId&0xFFFFFFFF))
	}
}

func renderKeyTag(k interface{}) string {
	switch key := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%dR", key.N.BitLen())
	case *dsa.PublicKey:
		return fmt.Sprintf("%dD", key.P.BitLen())
	default:
		return "??"
	}
}
