package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sebschat/cryptography"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"
	"sebschat/views"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func chatUI(win fyne.Window) fyne.CanvasObject {
	return widget.NewLabel("Chat View")
}

func settingsUI(win fyne.Window) fyne.CanvasObject {
	return widget.NewLabel("Settings View")
}

func main() {
	a := app.NewWithID("sebschat-client")
	w := a.NewWindow("SebsChat")

	// Check if config file exists
	if _, err := os.Stat("./config.json"); os.IsNotExist(err) {
		dialog.ShowError(fmt.Errorf("Config file not found. Please create a config.json file."), w)
		w.ShowAndRun()
		return
	}

	// Load config
	file, err := os.Open("./config.json")
	if err != nil {
		dialog.ShowError(fmt.Errorf("error opening config file: %v", err), w)
		w.ShowAndRun()
		return
	}
	defer file.Close()
	byteValue, err := io.ReadAll(file)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error reading config file: %v", err), w)
		w.ShowAndRun()
		return
	}
	err = json.Unmarshal(byteValue, &globals.Config)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error unmarshalling config: %v", err), w)
		w.ShowAndRun()
		return
	}

	// Check if user file exists
	if _, err := os.Stat(globals.Config.UserFilePath); os.IsNotExist(err) {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("Enter your name")
		form := widget.NewForm(
			widget.NewFormItem("Name", nameEntry),
		)
		form.OnSubmit = func() {
			name := nameEntry.Text
			if name == "" {
				dialog.ShowError(fmt.Errorf("Name cannot be empty"), w)
				return
			}

			priv, pub, err := cryptography.GenerateX25519KeyPair()
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			pubSign, privSign, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			selfUser := types.SelfUser{
				Name:              name,
				PublicKey:         utils.BytesToBase64(pub),
				PrivateKey:        utils.BytesToBase64(priv),
				SigningPublicKey:  utils.BytesToBase64(pubSign),
				SigningPrivateKey: utils.BytesToBase64(privSign),
			}

			globals.SelfUser = selfUser
			err = utils.SaveUser()
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			w.SetContent(mainAppContent(w))
		}
		w.SetContent(container.NewVBox(
			widget.NewLabel("User file not found. Please enter your name to create your user profile."),
			form,
		))
		w.ShowAndRun()
	}

	// Load user file
	file, err = os.Open(globals.Config.UserFilePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error opening user file: %v", err), w)
		w.ShowAndRun()
		return
	}
	defer file.Close()
	byteValue, err = io.ReadAll(file)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error reading user file: %v", err), w)
		w.ShowAndRun()
		return
	}
	err = json.Unmarshal(byteValue, &globals.SelfUser)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error unmarshalling user file: %v", err), w)
		w.ShowAndRun()
		return
	}

	// Contacts file
	var contacts types.Contacts
	if _, err := os.Stat(globals.Config.ContactsFilePath); os.IsNotExist(err) {
		contacts = types.Contacts{
			Contacts: []types.Contact{},
		}
		data, err := json.MarshalIndent(contacts, "", "  ")
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to marshal contacts: %v", err), w)
			return
		}
		err = os.WriteFile(globals.Config.ContactsFilePath, data, 0600)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to write contacts file: %v", err), w)
			return
		}
	}
	file, err = os.Open(globals.Config.ContactsFilePath)
	if err != nil {
		log.Fatalf("error opening contacts file: %v", err)
	}
	defer file.Close()
	byteValue, err = io.ReadAll(file)
	if err != nil {
		log.Fatalf("error reading contacts file: %v", err)
	}
	err = json.Unmarshal(byteValue, &contacts)
	if err != nil {
		log.Fatalf("error unmarshalling contacts file: %v", err)
	}
	globals.Contacts = contacts.Contacts

	w.SetContent(mainAppContent(w))
	w.Resize(fyne.NewSize(900, 700))
	w.ShowAndRun()
}

// Helper to return the main app content (your navigation etc.)
func mainAppContent(w fyne.Window) fyne.CanvasObject {
	content := container.NewStack(views.ContactsUI(w))
	var btnDecryptor, btnEncryptor, btnChat, btnSettings, btnContacts *widget.Button
	var navButtons *fyne.Container

	setActive := func(active string) {
		btnDecryptor.Importance = widget.MediumImportance
		btnEncryptor.Importance = widget.MediumImportance
		btnChat.Importance = widget.MediumImportance
		btnSettings.Importance = widget.MediumImportance
		btnContacts.Importance = widget.MediumImportance

		switch active {
		case "decryptor":
			btnDecryptor.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.MessageDecryptorUI(w)}
		case "encryptor":
			btnEncryptor.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.MessageEncryptorUI(w)}
		case "chat":
			btnChat.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{chatUI(w)}
		case "contacts":
			btnContacts.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.ContactsUI(w)}
		case "settings":
			btnSettings.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{settingsUI(w)}
		}
		content.Refresh()
		navButtons.Refresh()
	}

	btnDecryptor = widget.NewButtonWithIcon("Decrypt", theme.VisibilityIcon(), func() { setActive("decryptor") })
	btnEncryptor = widget.NewButtonWithIcon("Encrypt", theme.VisibilityOffIcon(), func() { setActive("encryptor") })
	btnChat = widget.NewButtonWithIcon("Chat", theme.MailSendIcon(), func() { setActive("chat") })
	btnContacts = widget.NewButtonWithIcon("Contacts", theme.AccountIcon(), func() { setActive("contacts") })
	btnSettings = widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() { setActive("settings") })

	navButtons = container.NewVBox(
		btnEncryptor,
		btnDecryptor,
		btnChat,
		btnContacts,
		btnSettings,
		layout.NewSpacer(),
	)

	navContainer := container.NewBorder(nil, nil, nil, widget.NewSeparator(),
		container.NewStack(navButtons))

	split := container.NewHSplit(navContainer, content)
	split.Offset = 0.2

	return split
}
