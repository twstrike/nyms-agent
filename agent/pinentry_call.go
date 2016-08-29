package agent

import (
	"io"
	"os/exec"
	"bufio"
  "fmt"
	"errors"
	"strings"
)

type Pinentry struct {
	input io.WriteCloser
	output io.ReadCloser
	cmd exec.Cmd
}

func NewPinentry() (*Pinentry, error) {
	cmd := *exec.Command("pinentry")

	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()

	if err != nil {
		return nil, err
	}

	fmt.Printf("%s\n", readLine(out))

	return &Pinentry {
		input : in,
		output: out,
		cmd: cmd,
	}, err
}

func (p Pinentry) Close() {
	p.input.Close()
  // XXX verify error. if it does fail should the process be killed?
	p.cmd.Wait()
}

func (p *Pinentry) InvokeGetPin() (pin string, err error) {
	p.input.Write([]byte("getpin\n"))
 	rawDataFlag := readLine(p.output)

	pin, err = asRawData(rawDataFlag)
	if err != nil {
		return "", err
	}

	//  Verify execution was succesful.
	//  This is hanging from time to time but don't understand why.
	
//	s := bufio.NewScanner(p.output)
//	var okFlag string
//	fmt.Println("1-----------")
//	s.Scan()
//	if err = s.Err(); err != nil {
//		return "", err
//	}
//		fmt.Println("2-----------")
//		okFlag = s.Text()
//
//	if !isExecGood(okFlag) {
//		fmt.Print("3-----------")
//		return "", errors.New("Execution failed")
//	}
//	
	return
}

func asRawData(raw string) (data string, err error) {
	if !strings.HasPrefix(raw, "D ") {
		return "", errors.New("This is not a raw data line.")
	}
	data = strings.TrimPrefix(raw, "D ")
	return 
}

func isExecGood(data string) bool {
	return data == "OK"
}

func readLine(reader io.Reader) (line string) {
	b := bufio.NewReader(reader)
	lineByte, _, err := b.ReadLine()
	if err != nil {
    return "failed to flush output"
	}
	
	return string(lineByte)
}
