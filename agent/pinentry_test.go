package agent

import "testing"

func TestPinentry(t *testing.T) {
	t.Skip("remove me if you want to test pinentry")
	c := NewPinentryClient("pinentry")
	pin, err := c.GetPin()
	c.Close()
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(pin)
}
