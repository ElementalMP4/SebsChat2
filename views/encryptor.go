package views

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func MessageEncryptorUI(win fyne.Window) fyne.CanvasObject {
	output := widget.NewLabel("Encrypt stuff amirite?")

	return container.NewVBox(output)
}
