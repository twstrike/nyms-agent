package hkps

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type Client interface {
	Submit(*openpgp.Entity) error
}

func NewClient(addr string) Client {
	return &client{addr}
}

type client struct {
	address string
}

func (c *client) path(abspath string) string {
	return c.address + abspath
}

func armoredKeyring(e *openpgp.Entity) (string, error) {
	dst := &bytes.Buffer{}
	// XXX Should we add a version header?
	armoredDst, err := armor.Encode(dst, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	defer armoredDst.Close()

	err = e.Serialize(armoredDst)
	if err != nil {
		return "", err
	}

	return dst.String(), nil
}

func (c *client) Submit(k *openpgp.Entity) error {
	kr, err := armoredKeyring(k)
	if err != nil {
		return err
	}

	data := url.Values{}
	data.Set("keytext", url.QueryEscape(kr))

	resp, err := http.PostForm(c.path("/pks/add"), data)
	if err != nil {
		return nil
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("hkps: unexpected response from server (%s)", resp.Status)
	}

	return nil
}
