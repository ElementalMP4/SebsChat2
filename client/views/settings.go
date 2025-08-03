package views

import (
	"fmt"
	"image/color"
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

	var (
		updateSaveBtn func()
		isChanged     func() bool
	)

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

	// Favourite Colour
	favouriteColour := user.FavouriteColour
	colourDisplay := widget.NewLabel("Selected: " + favouriteColour)
	colourBtn := widget.NewButton("Choose Colour", func() {
		dialog.NewColorPicker("Pick a Favourite Colour", "Choose a colour", func(c color.Color) {
			r, g, b, _ := c.RGBA()
			hex := fmt.Sprintf("#%02X%02X%02X", uint8(r>>8), uint8(g>>8), uint8(b>>8))
			favouriteColour = hex
			colourDisplay.SetText("Selected: " + hex)
			updateSaveBtn()
		}, win).Show()
	})

	// Store original values for change detection
	original := struct {
		Name, PublicKey, PrivateKey, SigningPublicKey, SigningPrivateKey, Address, FavouriteColour string
		UseTls                                                                                     bool
	}{
		Name:              user.Name,
		PublicKey:         user.PublicKey,
		PrivateKey:        user.PrivateKey,
		SigningPublicKey:  user.SigningPublicKey,
		SigningPrivateKey: user.SigningPrivateKey,
		Address:           user.Server.Address,
		FavouriteColour:   user.FavouriteColour,
		UseTls:            user.Server.UseTls,
	}

	// Helper to check if any field has changed
	isChanged = func() bool {
		return nameEntry.Text != original.Name ||
			publicKeyEntry.Text != original.PublicKey ||
			privateKeyEntry.Text != original.PrivateKey ||
			signingPublicKeyEntry.Text != original.SigningPublicKey ||
			signingPrivateKeyEntry.Text != original.SigningPrivateKey ||
			addressEntry.Text != original.Address ||
			useTlsCheck.Checked != original.UseTls ||
			favouriteColour != original.FavouriteColour
	}

	// Function to update save button state
	var saveBtn *widget.Button
	updateSaveBtn = func() {
		if saveBtn == nil {
			return
		}
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
			FavouriteColour:   favouriteColour,
			Server: types.Server{
				Address: addressEntry.Text,
				UseTls:  useTlsCheck.Checked,
				Token:   globals.SelfUser.Server.Token,
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
		original.FavouriteColour = favouriteColour

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
			widget.NewFormItem("Favourite Colour", container.NewVBox(colourBtn, colourDisplay)),
			widget.NewFormItem("Public Key", publicKeyEntry),
			widget.NewFormItem("Private Key", privateKeyEntry),
			widget.NewFormItem("Signing Public Key", signingPublicKeyEntry),
			widget.NewFormItem("Signing Private Key", signingPrivateKeyEntry),
			widget.NewFormItem("Server Address", addressEntry),
			widget.NewFormItem("", useTlsCheck),
		},
	}

	saveBtn.Alignment = widget.ButtonAlignCenter

	return container.NewVBox(
		utils.MakeHeaderLabel("Settings"),
		form,
		saveBtn,
	)
}
