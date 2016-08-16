package hkps

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

func TestHKPSSubmit(t *testing.T) {
	expectedArmored := "SOME ARMORED KEYRING"

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

	err = c.Submit(expectedArmored)
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
