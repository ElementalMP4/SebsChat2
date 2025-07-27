package views

import (
	"fmt"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func SettingsUI(win fyne.Window) fyne.CanvasObject {
	user := globals.SelfUser // assuming globals.SelfUser exists

	// User fields
	nameEntry := widget.NewEntry()
	nameEntry.SetText(user.Name)

	publicKeyEntry := widget.NewMultiLineEntry()
	publicKeyEntry.SetText(user.PublicKey)

	privateKeyEntry := widget.NewMultiLineEntry()
	privateKeyEntry.SetText(user.PrivateKey)

	signingPublicKeyEntry := widget.NewMultiLineEntry()
	signingPublicKeyEntry.SetText(user.SigningPublicKey)

	signingPrivateKeyEntry := widget.NewMultiLineEntry()
	signingPrivateKeyEntry.SetText(user.SigningPrivateKey)

	// Server fields
	addressEntry := widget.NewEntry()
	addressEntry.SetText(user.Server.Address)

	useTlsCheck := widget.NewCheck("Use TLS", func(b bool) {})
	useTlsCheck.SetChecked(user.Server.UseTls)

	saveBtn := widget.NewButton("Save", func() {
		globals.SelfUser = types.SelfUser{
			Name:              nameEntry.Text,
			PublicKey:         publicKeyEntry.Text,
			PrivateKey:        privateKeyEntry.Text,
			SigningPublicKey:  signingPublicKeyEntry.Text,
			SigningPrivateKey: signingPrivateKeyEntry.Text,
			Server: types.Server{
				Address: addressEntry.Text,
				UseTls:  useTlsCheck.Checked,
			},
		}

		if err := utils.SaveUser(); err != nil {
			dialog.ShowError(fmt.Errorf("failed to save settings: %v", err), win)
			return
		}
		dialog.ShowInformation("Settings", "Settings saved successfully.", win)
	})

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Public Key", publicKeyEntry),
			widget.NewFormItem("Private Key", privateKeyEntry),
			widget.NewFormItem("Signing Public Key", signingPublicKeyEntry),
			widget.NewFormItem("Signing Private Key", signingPrivateKeyEntry),
			widget.NewFormItem("Server Address", addressEntry),
			widget.NewFormItem("", useTlsCheck),
		},
	}

	return container.NewVBox(
		widget.NewLabelWithStyle("Settings", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		form,
		saveBtn,
	)
}
