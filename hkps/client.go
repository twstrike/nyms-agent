package hkps

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type Client interface {
	Submit(*openpgp.Entity) error
	Lookup(string) ([]*Index, error)
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

type Index struct {
	PrimaryKey
	UserIDs []UserID
}

type PrimaryKey struct {
	KeyId                      uint64
	Fingerprint                [20]byte
	PubKeyAlgo                 packet.PublicKeyAlgorithm
	KeyLen                     int
	CreationTime               time.Time
	ExpirationTime             time.Time
	Disabled, Expired, Revoked bool
}

type UserID struct {
	UserID                     string
	CreationTime               time.Time
	ExpirationTime             time.Time
	Disabled, Expired, Revoked bool
}

func parseIndexes(r io.Reader) ([]*Index, error) {
	s := bufio.NewScanner(r)

	ret := make([]*Index, 0, 1)
	for s.Scan() {
		tokens := strings.SplitN(s.Text(), ":", 7)

		switch tokens[0] {
		case "info":
			//stupid. Maybe check version and expand the array?
		case "pub":
			index, err := parsePrimaryKey(tokens)
			if err != nil {
				return ret, err
			}

			ret = append(ret, index)
		case "uid":
			uid, err := parseUserID(tokens)
			if err != nil {
				return ret, err
			}

			current := ret[len(ret)-1]
			current.UserIDs = append(current.UserIDs, uid)
		default:
			return nil, errors.New("unexpected type:" + tokens[0])
		}
	}

	return ret, s.Err()
}

func parsePrimaryKey(tokens []string) (ret *Index, err error) {
	if tokens[0] != "pub" {
		return
	}

	ret = &Index{}

	if tokens[1] != "" {
		var bs []byte
		bs, err = hex.DecodeString(tokens[1])
		if err != nil {
			return
		}

		switch len(bs) {
		case 8, 4:
			ret.KeyId = binary.BigEndian.Uint64(bs)
		case 20:
			copy(ret.Fingerprint[:], bs)
		default:
			//error
			return
		}
	}

	if tokens[2] != "" {
		var algo int
		algo, err = strconv.Atoi(tokens[2])
		if err != nil {
			return
		}

		ret.PubKeyAlgo = packet.PublicKeyAlgorithm(algo)
	}

	if tokens[3] != "" {
		ret.KeyLen, err = strconv.Atoi(tokens[3])
		if err != nil {
			return
		}
	}

	ret.CreationTime, err = parseTime(tokens[4])
	if err != nil {
		return
	}

	ret.ExpirationTime, err = parseTime(tokens[5])
	if err != nil {
		return
	}

	if tokens[6] != "" {
		ret.Revoked = strings.ContainsRune(tokens[6], 'r')
		ret.Disabled = strings.ContainsRune(tokens[6], 'd')
		ret.Expired = strings.ContainsRune(tokens[6], 'e')
	}

	ret.UserIDs = make([]UserID, 0, 0)

	return
}

func parseTime(in string) (time.Time, error) {
	var r time.Time

	if in == "" {
		return r, nil
	}

	t, err := strconv.ParseInt(in, 10, 64)
	if err != nil {
		return r, err
	}

	return time.Unix(t, 0), nil
}

func parseUserID(tokens []string) (ret UserID, err error) {
	if tokens[0] != "uid" {
		return
	}

	ret.UserID = tokens[1]
	ret.CreationTime, err = parseTime(tokens[2])
	if err != nil {
		return
	}

	ret.ExpirationTime, err = parseTime(tokens[3])
	if err != nil {
		return
	}

	if tokens[4] != "" {
		ret.Revoked = strings.ContainsRune(tokens[4], 'r')
		ret.Disabled = strings.ContainsRune(tokens[4], 'd')
		ret.Expired = strings.ContainsRune(tokens[4], 'e')
	}

	return
}

func (c *client) Lookup(search string) ([]*Index, error) {
	p := url.Values{}
	p.Set("op", "index")
	p.Set("options", "mr")
	p.Set("search", search)

	resp, err := http.Get(c.path("/pks/lookup?" + p.Encode()))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hkps: unexpected response from server (%s)", resp.Status)
	}

	return parseIndexes(resp.Body)
}
