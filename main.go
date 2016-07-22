package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"

	gl "github.com/op/go-logging"
	"github.com/twstrike/nyms-agent/keymgr"
	"github.com/twstrike/nyms-agent/pipes"
)

var pipe bool
var protoDebug bool

func init() {
	flag.BoolVar(&pipe, "pipe", false, "Run RPC service on stdin/stdout")
	flag.BoolVar(&protoDebug, "debug", false, "Log RPC traffic")
	flag.Parse()
}

func main() {
	createLogger()
	if pipe {
		keymgr.LoadDefaultKeyring()
		pipes.RunPipeServer(os.Stdin, os.Stdout, protoDebug)
		return
	}
}

const defaultLogPath = ".nyms/log"

func createLogger() {
	f, err := openLogFile()
	if err != nil {
		return
	}
	be := gl.NewLogBackend(f, "", log.Ltime)
	gl.SetBackend(be)
}

func openLogFile() (io.Writer, error) {
	logPath := getLogPath()
	dirPath := filepath.Dir(logPath)
	err := os.MkdirAll(dirPath, 0711)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

func getLogPath() string {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("Failed to get current user information: %v", err))
	}
	return filepath.Join(u.HomeDir, defaultLogPath)
}
