package hkps

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var expectedArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
`

func TestWriteArmoredKeyRing(t *testing.T) {
	f, err := os.Open("../testdata/keypair.asc")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	e, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(e) != 1 {
		panic(err)
	}

	armored, err := armoredKeyring(e[0])
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if armored != expectedArmored {
		t.Fatalf("armored keyring does not match")
	}
}

func TestHKPSSubmit(t *testing.T) {
	f, err := os.Open("../testdata/keypair.asc")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	e, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(e) != 1 {
		panic(err)
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pks/add" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		err := r.ParseForm()
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		keytext := r.PostForm.Get("keytext")
		if keytext != expectedArmored {
			t.Errorf("unexpected keytext: %s", keytext)
		}
	}
	s := httptest.NewServer(http.HandlerFunc(fn))

	c, err := NewClient(s.URL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	err = c.Submit(e[0])
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestHKPSIndex(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pks/lookup" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		err := r.ParseForm()
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		op := r.Form.Get("op")
		if op != "index" {
			t.Errorf("unexpected op: %s", op)
		}

		options := r.Form.Get("options")
		if options != "mr" {
			t.Errorf("unexpected options: %s", options)
		}

		search := r.Form.Get("search")
		if search != "nyms-agent" {
			t.Errorf("unexpected search: %s", search)
		}

		w.Write([]byte("info:1:1\n"))
		w.Write([]byte("pub:97372B211CADF401:1:4096:1470692529::\n"))
		w.Write([]byte("uid:Nyms Agent (for testing purposes) <agent@nyms.io>:1470692529::\n"))
	}

	s := httptest.NewServer(http.HandlerFunc(fn))

	c, err := NewClient(s.URL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	entities, err := c.Lookup("nyms-agent")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(entities) != 1 {
		t.Errorf("unexpected response: %s", entities)
	}

}

func TestParseIndexesInMachineFormat(t *testing.T) {
	input := `info:1:1
pub:97372B211CADF401:1:4096:1470692529::
uid:Nyms Agent (for testing purposes) <agent@nyms.io>:1470692529::`

	expected := &Index{
		PrimaryKey: PrimaryKey{
			KeyId:        0x97372B211CADF401,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			KeyLen:       4096,
			CreationTime: time.Unix(1470692529, 0),
		},
		UserIDs: []UserID{
			UserID{
				UserID:       "Nyms Agent (for testing purposes) <agent@nyms.io>",
				CreationTime: time.Unix(1470692529, 0),
			},
		},
	}

	r := bytes.NewBufferString(input)
	entities, err := parseIndexes(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(entities) != 1 {
		t.Errorf("unexpected response: %s", entities)
	}

	if !reflect.DeepEqual(entities[0], expected) {
		t.Errorf("unexpected response: %#v", entities[0])
	}
}

func TestParsePrimaryKey(t *testing.T) {
	input := "pub:97372B211CADF401:1:4096:1470692529:1470692590:de"
	tokens := strings.SplitN(input, ":", 7)
	index, err := parsePrimaryKey(tokens)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if index.KeyId != 0x97372B211CADF401 {
		t.Errorf("unexpected KeyID: %x", index.KeyId)
	}

	if index.PubKeyAlgo != packet.PubKeyAlgoRSA {
		t.Errorf("unexpected PubKeyAlgo: %d", index.PubKeyAlgo)
	}

	if index.KeyLen != 4096 {
		t.Errorf("unexpected KeyLen: %d", index.KeyLen)
	}

	if !index.CreationTime.Equal(time.Unix(1470692529, 0)) {
		t.Errorf("unexpected CreationTime: %s", index.CreationTime)
	}

	if !index.ExpirationTime.Equal(time.Unix(1470692590, 0)) {
		t.Errorf("unexpected ExpirationTime: %s", index.ExpirationTime)
	}

	if !index.Disabled {
		t.Errorf("unexpected Disabled: %t", index.Disabled)
	}

	if !index.Expired {
		t.Errorf("unexpected Expired: %t", index.Expired)
	}

	if index.Revoked {
		t.Errorf("unexpected Revoked: %t", index.Revoked)
	}
}

func TestParseUserID(t *testing.T) {
	input := "uid:Nyms Agent (for testing purposes) <agent@nyms.io>:1470692529:1470692590:rd"
	tokens := strings.SplitN(input, ":", 7)
	userID, err := parseUserID(tokens)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if userID.UserID != "Nyms Agent (for testing purposes) <agent@nyms.io>" {
		t.Errorf("unexpected UserID: %q", userID.UserID)
	}

	if !userID.CreationTime.Equal(time.Unix(1470692529, 0)) {
		t.Errorf("unexpected CreationTime: %s", userID.CreationTime)
	}

	if !userID.ExpirationTime.Equal(time.Unix(1470692590, 0)) {
		t.Errorf("unexpected ExpirationTime: %s", userID.ExpirationTime)
	}

	if !userID.Disabled {
		t.Errorf("unexpected Disabled: %t", userID.Disabled)
	}

	if userID.Expired {
		t.Errorf("unexpected Expired: %t", userID.Expired)
	}

	if !userID.Revoked {
		t.Errorf("unexpected Revoked: %t", userID.Revoked)
	}
}
