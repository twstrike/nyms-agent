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

func translateProtocol(u *url.URL) *url.URL {
	if u.Scheme == "hpks" {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}

	return u
}

//XXX HKP clients SHOULD support SRV records.
//XXX Support doing everything over Tor?
func NewClient(addr string) (Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	return &client{translateProtocol(u)}, nil
}

type client struct {
	base *url.URL
}

func (c *client) path(p string) string {
	ref, err := url.Parse(p)
	if err != nil {
		panic(err)
	}

	return c.base.ResolveReference(ref).String()
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
	data.Set("keytext", kr)

	resp, err := http.PostForm(c.path("/pks/add"), data)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("hkps: unexpected response from server (%s)", resp.Status)
	}

	//XXX Should we parse the response and return more info, like:
	// {"inserted":["rsa4096/579ebcb26c9772cdb7a896f297372b211cadf401"],"updated":null,"ignored":null}

	return nil
}
