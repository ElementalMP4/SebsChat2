package views

import (
	"encoding/base64"
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

	// Public Key fields
	x25519PubEntry := widget.NewMultiLineEntry()
	x25519PubEntry.SetText(user.Keys.Public.X25519Pub)
	kyberPubEntry := widget.NewMultiLineEntry()
	kyberPubEntry.SetText(user.Keys.Public.PQKemPub)
	edPubEntry := widget.NewMultiLineEntry()
	edPubEntry.SetText(user.Keys.Public.EdPub)
	mldsaPubEntry := widget.NewMultiLineEntry()
	mldsaPubEntry.SetText(user.Keys.Public.PQSignPub)

	// Private Key fields
	x25519PrivEntry := widget.NewMultiLineEntry()
	x25519PrivEntry.SetText(user.Keys.Private.X25519Priv)
	kyberPrivEntry := widget.NewMultiLineEntry()
	kyberPrivEntry.SetText(user.Keys.Private.PQKemPriv)
	edPrivEntry := widget.NewMultiLineEntry()
	edPrivEntry.SetText(user.Keys.Private.EdPriv)
	mldsaPrivEntry := widget.NewMultiLineEntry()
	mldsaPrivEntry.SetText(user.Keys.Private.PQSignPriv)

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
		Name, FavouriteColour, Address           string
		UseTls                                   bool
		X25519Pub, KyberPub, EdPub, MldsaPub     string
		X25519Priv, KyberPriv, EdPriv, MldsaPriv string
	}{
		Name:            user.Name,
		FavouriteColour: user.FavouriteColour,
		Address:         user.Server.Address,
		UseTls:          user.Server.UseTls,
		X25519Pub:       x25519PubEntry.Text,
		KyberPub:        kyberPubEntry.Text,
		EdPub:           edPubEntry.Text,
		MldsaPub:        mldsaPubEntry.Text,
		X25519Priv:      x25519PrivEntry.Text,
		KyberPriv:       kyberPrivEntry.Text,
		EdPriv:          edPrivEntry.Text,
		MldsaPriv:       mldsaPrivEntry.Text,
	}

	// Helper to check if any field has changed
	isChanged = func() bool {
		return nameEntry.Text != original.Name ||
			x25519PubEntry.Text != original.X25519Pub ||
			kyberPubEntry.Text != original.KyberPub ||
			edPubEntry.Text != original.EdPub ||
			mldsaPubEntry.Text != original.MldsaPub ||
			x25519PrivEntry.Text != original.X25519Priv ||
			kyberPrivEntry.Text != original.KyberPriv ||
			edPrivEntry.Text != original.EdPriv ||
			mldsaPrivEntry.Text != original.MldsaPriv ||
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
		// Decode all keys from base64
		x25519Pub, err := base64.StdEncoding.DecodeString(x25519PubEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid X25519 public key: %v", err), win)
			return
		}
		kyberPub, err := base64.StdEncoding.DecodeString(kyberPubEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid Kyber768 public key: %v", err), win)
			return
		}
		edPub, err := base64.StdEncoding.DecodeString(edPubEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid Ed25519 public key: %v", err), win)
			return
		}
		mldsaPub, err := base64.StdEncoding.DecodeString(mldsaPubEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid MLDSA65 public key: %v", err), win)
			return
		}
		x25519Priv, err := base64.StdEncoding.DecodeString(x25519PrivEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid X25519 private key: %v", err), win)
			return
		}
		kyberPriv, err := base64.StdEncoding.DecodeString(kyberPrivEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid Kyber768 private key: %v", err), win)
			return
		}
		edPriv, err := base64.StdEncoding.DecodeString(edPrivEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid Ed25519 private key: %v", err), win)
			return
		}
		mldsaPriv, err := base64.StdEncoding.DecodeString(mldsaPrivEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid MLDSA65 private key: %v", err), win)
			return
		}

		globals.SelfUser = types.SelfUser{
			Name:            nameEntry.Text,
			FavouriteColour: favouriteColour,
			Server: types.Server{
				Address: addressEntry.Text,
				UseTls:  useTlsCheck.Checked,
				Token:   globals.SelfUser.Server.Token,
			},
			Keys: types.HybridKeypair{
				Public: types.HybridPublicKeys{
					X25519Pub: utils.BytesToBase64(x25519Pub),
					PQKemPub:  utils.BytesToBase64(kyberPub),
					EdPub:     utils.BytesToBase64(edPub),
					PQSignPub: utils.BytesToBase64(mldsaPub),
				},
				Private: types.HybridPrivateKeys{
					X25519Priv: utils.BytesToBase64(x25519Priv),
					PQKemPriv:  utils.BytesToBase64(kyberPriv),
					EdPriv:     utils.BytesToBase64(edPriv),
					PQSignPriv: utils.BytesToBase64(mldsaPriv),
				},
			},
		}

		if err := utils.SaveUser(); err != nil {
			dialog.ShowError(fmt.Errorf("failed to save settings: %v", err), win)
			return
		}

		// Update original values after save
		original.Name = nameEntry.Text
		original.FavouriteColour = favouriteColour
		original.Address = addressEntry.Text
		original.UseTls = useTlsCheck.Checked
		original.X25519Pub = x25519PubEntry.Text
		original.KyberPub = kyberPubEntry.Text
		original.EdPub = edPubEntry.Text
		original.MldsaPub = mldsaPubEntry.Text
		original.X25519Priv = x25519PrivEntry.Text
		original.KyberPriv = kyberPrivEntry.Text
		original.EdPriv = edPrivEntry.Text
		original.MldsaPriv = mldsaPrivEntry.Text

		updateSaveBtn()
	})
	saveBtn.Importance = widget.HighImportance
	updateSaveBtn() // Initial state

	// Attach listeners to all fields
	nameEntry.OnChanged = func(_ string) { updateSaveBtn() }
	x25519PubEntry.OnChanged = func(_ string) { updateSaveBtn() }
	kyberPubEntry.OnChanged = func(_ string) { updateSaveBtn() }
	edPubEntry.OnChanged = func(_ string) { updateSaveBtn() }
	mldsaPubEntry.OnChanged = func(_ string) { updateSaveBtn() }
	x25519PrivEntry.OnChanged = func(_ string) { updateSaveBtn() }
	kyberPrivEntry.OnChanged = func(_ string) { updateSaveBtn() }
	edPrivEntry.OnChanged = func(_ string) { updateSaveBtn() }
	mldsaPrivEntry.OnChanged = func(_ string) { updateSaveBtn() }
	addressEntry.OnChanged = func(_ string) { updateSaveBtn() }
	useTlsCheck.OnChanged = func(_ bool) { updateSaveBtn() }

	// Group public and private keys
	publicKeysGroup := container.NewVBox(
		widget.NewLabel("Public Keys (base64):"),
		widget.NewForm(
			widget.NewFormItem("X25519", x25519PubEntry),
			widget.NewFormItem("Kyber768", kyberPubEntry),
			widget.NewFormItem("Ed25519", edPubEntry),
			widget.NewFormItem("MLDSA65", mldsaPubEntry),
		),
	)
	privateKeysGroup := container.NewVBox(
		widget.NewLabel("Private Keys (base64):"),
		widget.NewForm(
			widget.NewFormItem("X25519", x25519PrivEntry),
			widget.NewFormItem("Kyber768", kyberPrivEntry),
			widget.NewFormItem("Ed25519", edPrivEntry),
			widget.NewFormItem("MLDSA65", mldsaPrivEntry),
		),
	)

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Favourite Colour", container.NewVBox(colourBtn, colourDisplay)),
			widget.NewFormItem("Server Address", addressEntry),
			widget.NewFormItem("", useTlsCheck),
			widget.NewFormItem("", publicKeysGroup),
			widget.NewFormItem("", privateKeysGroup),
		},
	}

	saveBtn.Alignment = widget.ButtonAlignCenter

	return container.NewVBox(
		utils.MakeHeaderLabel("Settings"),
		form,
		saveBtn,
	)
}
