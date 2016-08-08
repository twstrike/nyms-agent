package main

import (
	"github.com/twstrike/nyms-agent/gui"

	"github.com/twstrike/gotk3adapter/gdka"
	"github.com/twstrike/gotk3adapter/gliba"
	"github.com/twstrike/gotk3adapter/gtka"
	"github.com/twstrike/gotk3adapter/pangoa"
)

//XXX This should be a separate app.
func runClient() {
	g := gui.CreateGraphics(
		gtka.Real,
		gliba.Real,
		gdka.Real,
		pangoa.Real,
	)

	gui.NewGTK(g).Loop()
}
