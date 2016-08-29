package agent

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
)

type pinentry interface {
	SetDesc(desc string)
	SetPrompt(prompt string)
	SetTitle(title string)
	SetOK(ok string)
	SetCancel(cancel string)
	SetError(errorMsg string)
	SetQualityBar()
	SetQualityBarTT(tt string)
	GetPin() (pin string, err error)
	Confirm() bool
	Close()
}

type pinentryClient struct {
	in   io.WriteCloser
	pipe *bufio.Reader
}

func (c *pinentryClient) SetDesc(desc string) {
	c.in.Write([]byte("SETDESC " + desc + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetPrompt(prompt string) {
	c.in.Write([]byte("SETPROMPT " + prompt + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetTitle(title string) {
	c.in.Write([]byte("SETTITLE " + title + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetOK(okLabel string) {
	c.in.Write([]byte("SETOK " + okLabel + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetCancel(cancelLabel string) {
	c.in.Write([]byte("SETCANCEL " + cancelLabel + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetError(errorMsg string) {
	c.in.Write([]byte("SETERROR " + errorMsg + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetQualityBar() {
	c.in.Write([]byte("SETQUALITYBAR\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) SetQualityBarTT(tt string) {
	c.in.Write([]byte("SETQUALITYBAR_TT" + tt + "\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) != 0 {
		panic(string(ok))
	}
}

func (c *pinentryClient) Confirm() bool {
	confirmed := false
	c.in.Write([]byte("CONFIRM\n"))
	// ok
	ok, _, _ := c.pipe.ReadLine()
	if bytes.Compare(ok, []byte("OK")) == 0 {
		confirmed = true
	}
	return confirmed
}

//XXX Shouldn't we always use []byte for pin?
func (c *pinentryClient) GetPin() (pin string, err error) {
	c.in.Write([]byte("GETPIN\n"))
	// D pin
	d_pin, _, err := c.pipe.ReadLine()
	return asRawData(string(d_pin))
}

func (c *pinentryClient) Close() {
	c.in.Close()
	return
}

func NewPinentryClient(path string) pinentry {
	cmd := exec.Command(path)
	in, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	bufout := bufio.NewReader(out)
	err = cmd.Start()
	if err != nil {
		panic(err)
	}
	// welcome
	welcome, _, _ := bufout.ReadLine()
	if bytes.Compare(welcome[:2], []byte("OK")) != 0 {
		panic(string(welcome))
	}
	return &pinentryClient{in, bufout}
}

func asRawData(raw string) (data string, err error) {
	if !strings.HasPrefix(raw, "D ") {
		return "", errors.New("This is not a raw data line.")
	}
	data = strings.TrimPrefix(raw, "D ")
	return
}
