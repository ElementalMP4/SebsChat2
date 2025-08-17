package views

import (
	"fmt"
	"sebschat/cryptography"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func MessageEncryptorUI(win fyne.Window) fyne.CanvasObject {
	contacts := utils.GetContactNames()

	selectedRecipients := []string{}
	var recipientsButton *widget.Button
	recipientsButton = widget.NewButton("Select recipients...", func() {
		checkGroup := widget.NewCheckGroup(contacts, func(selected []string) {
			selectedRecipients = selected
		})
		checkGroup.SetSelected(selectedRecipients)

		dlg := dialog.NewCustomConfirm(
			"Select Recipients",
			"OK",
			"Cancel",
			container.NewVScroll(checkGroup),
			func(ok bool) {
				if ok {
					if len(selectedRecipients) == 0 {
						recipientsButton.SetText("Select recipients...")
					} else {
						recipientsButton.SetText(fmt.Sprintf("%d selected", len(selectedRecipients)))
					}
				}
			},
			win,
		)
		dlg.Resize(fyne.NewSize(300, 400))
		dlg.Show()
	})

	messageBoxes := []*widget.Entry{}
	messageList := container.NewVBox()

	addMessageBox := func() {
		entry := widget.NewMultiLineEntry()
		entry.SetPlaceHolder("Type part of your message...")

		// Container that holds the entry + delete button
		var boxContainer *fyne.Container
		boxContainer = container.NewBorder(nil, nil, nil,
			widget.NewButton("Delete", func() {
				if len(messageBoxes) <= 1 {
					return // enforce at least one
				}
				// Remove from slices
				for i, e := range messageBoxes {
					if e == entry {
						messageBoxes = append(messageBoxes[:i], messageBoxes[i+1:]...)
						break
					}
				}
				messageList.Remove(boxContainer)
				messageList.Refresh()
			}),
			entry,
		)

		messageBoxes = append(messageBoxes, entry)
		messageList.Add(boxContainer)
		messageList.Refresh()
	}

	addMessageBox()

	encryptAndSave := func() {
		if len(selectedRecipients) == 0 {
			dialog.ShowError(fmt.Errorf("no recipients selected"), win)
			return
		}

		var parts []string
		for _, e := range messageBoxes {
			if e.Text != "" {
				parts = append(parts, e.Text)
			}
		}
		if len(parts) == 0 {
			dialog.ShowError(fmt.Errorf("no message content entered"), win)
			return
		}

		encryptedData, err := encryptMessages(selectedRecipients, parts)
		if err != nil {
			dialog.ShowError(err, win)
			return
		}

		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()

			messageBytes, err := utils.MessageToJson(encryptedData)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}

			_, wErr := writer.Write(messageBytes)
			if wErr != nil {
				dialog.ShowError(wErr, win)
				return
			}
			dialog.ShowInformation("Success", "Encrypted message saved!", win)
		}, win)
		fd.SetFileName("encrypted_message.enc")
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".enc"}))
		fd.Show()
	}

	return container.NewVBox(
		utils.MakeHeaderLabel("Encrypt a message"),
		widget.NewLabel("Recipients:"),
		recipientsButton,
		widget.NewSeparator(),
		widget.NewLabel("Message Parts:"),
		messageList,
		widget.NewButton("Add More Text", func() { addMessageBox() }),
		widget.NewButton("Encrypt & Save", encryptAndSave),
	)
}

func encryptMessages(recipients []string, messages []string) (types.EncryptedMessage, error) {
	var objects []types.MessageObject
	metadataMap := map[string]string{
		"favouriteColour": globals.SelfUser.FavouriteColour,
	}

	objects = append(objects, types.MessageObject{
		Type:    "metadata",
		Content: metadataMap,
	})
	for _, message := range messages {
		contentMap := map[string]string{
			"text": message,
		}
		objects = append(objects, types.MessageObject{
			Type:    "text",
			Content: contentMap,
		})
	}

	input := types.InputMessage{
		Recipients: recipients,
		Objects:    objects,
	}
	encrypted, err := cryptography.Encrypt(input)
	if err != nil {
		return types.EncryptedMessage{}, err
	}
	return *encrypted, nil
}
