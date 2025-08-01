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
	user := globals.SelfUser

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

	// Store original values for change detection
	original := struct {
		Name, PublicKey, PrivateKey, SigningPublicKey, SigningPrivateKey, Address string
		UseTls                                                                    bool
	}{
		Name:              user.Name,
		PublicKey:         user.PublicKey,
		PrivateKey:        user.PrivateKey,
		SigningPublicKey:  user.SigningPublicKey,
		SigningPrivateKey: user.SigningPrivateKey,
		Address:           user.Server.Address,
		UseTls:            user.Server.UseTls,
	}

	// Helper to check if any field has changed
	isChanged := func() bool {
		return nameEntry.Text != original.Name ||
			publicKeyEntry.Text != original.PublicKey ||
			privateKeyEntry.Text != original.PrivateKey ||
			signingPublicKeyEntry.Text != original.SigningPublicKey ||
			signingPrivateKeyEntry.Text != original.SigningPrivateKey ||
			addressEntry.Text != original.Address ||
			useTlsCheck.Checked != original.UseTls
	}

	// Function to update save button state
	var saveBtn *widget.Button
	updateSaveBtn := func() {
		saveBtn.Disable()
		if isChanged() {
			saveBtn.Enable()
		}
	}

	saveBtn = widget.NewButton("Save", func() {
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

		// Update original values after save
		original.Name = nameEntry.Text
		original.PublicKey = publicKeyEntry.Text
		original.PrivateKey = privateKeyEntry.Text
		original.SigningPublicKey = signingPublicKeyEntry.Text
		original.SigningPrivateKey = signingPrivateKeyEntry.Text
		original.Address = addressEntry.Text
		original.UseTls = useTlsCheck.Checked

		updateSaveBtn()
	})
	saveBtn.Importance = widget.HighImportance
	updateSaveBtn() // Initial state

	// Attach listeners to all fields
	nameEntry.OnChanged = func(_ string) { updateSaveBtn() }
	publicKeyEntry.OnChanged = func(_ string) { updateSaveBtn() }
	privateKeyEntry.OnChanged = func(_ string) { updateSaveBtn() }
	signingPublicKeyEntry.OnChanged = func(_ string) { updateSaveBtn() }
	signingPrivateKeyEntry.OnChanged = func(_ string) { updateSaveBtn() }
	addressEntry.OnChanged = func(_ string) { updateSaveBtn() }
	useTlsCheck.OnChanged = func(_ bool) { updateSaveBtn() }

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

	// Set buttons to stretch
	saveBtn.Alignment = widget.ButtonAlignCenter

	saveBtn.Importance = widget.HighImportance

	return container.NewVBox(
		utils.MakeHeaderLabel("Settings"),
		form,
		saveBtn,
	)
}
