package main

import (
	"encoding/json"
	"fmt"
	"io"
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

func main() {
	a := app.NewWithID("sebschat-client")
	w := a.NewWindow("SebsChat")
	w.Resize(fyne.NewSize(900, 700))

	// Get config path from environment variable or default
	configPath := os.Getenv("SC_CONFIG")
	if configPath == "" {
		configPath = "./config.json"
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		globals.Config = types.Config{
			UserFilePath:     "./profile.json",
			ContactsFilePath: "./contacts.json",
		}
	} else {
		// Load config
		file, err := os.Open(configPath)
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
				dialog.ShowError(fmt.Errorf("name cannot be empty"), w)
				return
			}

			keys, err := cryptography.GenerateHybridKeypair()
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			selfUser := types.SelfUser{
				Name:            name,
				Keys:            *keys,
				FavouriteColour: "#FFFFFF",
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
	file, err := os.Open(globals.Config.UserFilePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error opening user file: %v", err), w)
		w.ShowAndRun()
		return
	}
	defer file.Close()
	byteValue, err := io.ReadAll(file)
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
			dialog.ShowError(fmt.Errorf("failed to marshal contacts: %v", err), w)
			return
		}
		err = os.WriteFile(globals.Config.ContactsFilePath, data, 0600)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to write contacts file: %v", err), w)
			return
		}
	}
	file, err = os.Open(globals.Config.ContactsFilePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error opening contacts file: %v", err), w)
		return
	}
	defer file.Close()
	byteValue, err = io.ReadAll(file)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error reading contacts file: %v", err), w)
	}
	err = json.Unmarshal(byteValue, &contacts)
	if err != nil {
		dialog.ShowError(fmt.Errorf("error unmarshalling contacts file: %v", err), w)
	}
	globals.Contacts = contacts.Contacts

	w.SetContent(mainAppContent(w))
	w.ShowAndRun()
}

// Helper to return the main app content (your navigation etc.)
func mainAppContent(w fyne.Window) fyne.CanvasObject {
	content := container.NewStack()
	var btnDecryptor, btnEncryptor, btnChat, btnSettings, btnContacts, btnAccount *widget.Button
	var navButtons *fyne.Container

	setActive := func(active string) {
		btnDecryptor.Importance = widget.MediumImportance
		btnEncryptor.Importance = widget.MediumImportance
		btnChat.Importance = widget.MediumImportance
		btnSettings.Importance = widget.MediumImportance
		btnContacts.Importance = widget.MediumImportance
		btnAccount.Importance = widget.MediumImportance

		switch active {
		case "decryptor":
			btnDecryptor.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.MessageDecryptorUI(w)}
		case "encryptor":
			btnEncryptor.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.MessageEncryptorUI(w)}
		case "chat":
			btnChat.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.ChatUI(w)}
		case "contacts":
			btnContacts.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.ContactsUI(w)}
		case "settings":
			btnSettings.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.SettingsUI(w)}
		case "account":
			btnAccount.Importance = widget.HighImportance
			content.Objects = []fyne.CanvasObject{views.AccountUI(w)}
		}
		content.Refresh()
		navButtons.Refresh()
	}

	btnDecryptor = widget.NewButtonWithIcon("Decrypt", theme.VisibilityIcon(), func() { setActive("decryptor") })
	btnEncryptor = widget.NewButtonWithIcon("Encrypt", theme.VisibilityOffIcon(), func() { setActive("encryptor") })
	btnContacts = widget.NewButtonWithIcon("Contacts", theme.FolderIcon(), func() { setActive("contacts") })
	btnSettings = widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() { setActive("settings") })
	btnChat = widget.NewButtonWithIcon("Chat", theme.MailSendIcon(), func() { setActive("chat") })
	btnAccount = widget.NewButtonWithIcon("Account", theme.AccountIcon(), func() { setActive("account") })

	navButtons = container.NewVBox(
		utils.MakeHeaderLabel("SebsChat"),
		btnEncryptor,
		btnDecryptor,
		btnChat,
		btnContacts,
		btnAccount,
		btnSettings,
		layout.NewSpacer(),
	)

	navContainer := container.NewBorder(nil, nil, nil, widget.NewSeparator(),
		container.NewStack(navButtons))

	split := container.NewHSplit(navContainer, content)
	split.Offset = 0.2

	setActive("encryptor")

	return split
}
