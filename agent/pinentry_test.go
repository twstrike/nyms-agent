package agent

import "testing"

func TestPinentry(t *testing.T) {
	t.Skip("remove me if you want to test pinentry")
	c := NewPinentryClient("pinentry")
	defer c.Close()
	c.SetTitle("Nyms-agent pinentry")
	c.SetDesc("Nyms-agent asking your passphrase...")
	c.SetPrompt("PIN please:")
	c.SetCancel("Wait")
	c.SetOK("Fine")
	pin, err := c.GetPin()
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(pin)
}
