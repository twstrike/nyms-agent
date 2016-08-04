package gui

import (
	"fmt"
	"os"
	"runtime"

	"github.com/twstrike/coyim/config"
	"github.com/twstrike/gotk3adapter/gdki"
	"github.com/twstrike/gotk3adapter/glibi"
	"github.com/twstrike/gotk3adapter/gtki"
	"github.com/twstrike/gotk3adapter/pangoi"
)

const (
	programName        = "nyms-agent"
	applicationID      = "io.nyms.agent"
	localizationDomain = "nyms"
)

var g Graphics

// Graphics represent the graphic configuration
type Graphics struct {
	gtk   gtki.Gtk
	glib  glibi.Glib
	gdk   gdki.Gdk
	pango pangoi.Pango
}

// CreateGraphics creates a Graphic represention from the given arguments
func CreateGraphics(gtkVal gtki.Gtk, glibVal glibi.Glib, gdkVal gdki.Gdk, pangoVal pangoi.Pango) Graphics {
	return Graphics{
		gtk:   gtkVal,
		glib:  glibVal,
		gdk:   gdkVal,
		pango: pangoVal,
	}
}

func argsWithApplicationName() *[]string {
	newSlice := make([]string, len(os.Args))
	copy(newSlice, os.Args)
	newSlice[0] = programName
	return &newSlice
}

// UI is the user interface functionality exposed to main
type UI interface {
	Loop()
}

type gtkUI struct {
	app    gtki.Application
	window gtki.ApplicationWindow
}

// NewGTK returns a new client for a GTK ui
func NewGTK(gx Graphics) UI {
	runtime.LockOSThread()
	g = gx

	//*.mo files should be in ./i18n/locale_code.utf8/LC_MESSAGES/
	g.glib.InitI18n(localizationDomain, "./i18n")
	g.gtk.Init(argsWithApplicationName())

	var err error
	flags := glibi.APPLICATION_FLAGS_NONE
	if *config.MultiFlag {
		flags = glibi.APPLICATION_NON_UNIQUE
	}

	ret := &gtkUI{}

	ret.app, err = g.gtk.ApplicationNew(applicationID, flags)
	if err != nil {
		panic(err)
	}

	return ret
}

func (u *gtkUI) Loop() {
	u.app.Connect("activate", func() {
		activeWindow := u.app.GetActiveWindow()
		if activeWindow == nil {
			u.mainWindow()
		} else {
			activeWindow.Present()
		}
	})

	u.app.Run([]string{})
}

func (u *gtkUI) mainWindow() {
	builder := newBuilder("Main")
	win, err := builder.GetObject("mainWindow")

	if err != nil {
		panic(err)
	}
	builder.ConnectSignals(map[string]interface{}{
		"on_generate_key_dialog_signal": u.generateDialog,
	})
	u.window = win.(gtki.ApplicationWindow)
	u.window.SetApplication(u.app)
	u.window.ShowAll()
}

func (u *gtkUI) generateDialog() {
	builder := newBuilder("GenerateKeys")
	obj, err := builder.GetObject("generateDialog")
	if err != nil {
		panic(err)
	}
	generateDialog := obj.(gtki.Dialog)
	generateDialog.Connect("response", func(_ interface{}, rid int) {
		if gtki.ResponseType(rid) == gtki.RESPONSE_OK {
			obj, err := builder.GetObject("email-entry")
			if err != nil {
				panic(err)
			}
			email, _ := obj.(gtki.Entry).GetText()
			obj, err = builder.GetObject("real-name-entry")
			if err != nil {
				panic(err)
			}
			realName, _ := obj.(gtki.Entry).GetText()
			go generateNewKey(realName, email)
		}
		generateDialog.Destroy()
	})
	generateDialog.SetTransientFor(u.window)
	generateDialog.Run()
}

func generateNewKey(realName, email string) {
	keyinfo := new(client).createKeyPair(realName, email, "")
	fmt.Printf("%v", keyinfo)
}
