package views

import (
	"fmt"
	"sebschat/utils"
	"strings"

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
		messageBoxes = append(messageBoxes, entry)
		messageList.Add(entry)
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

		encryptedData := fakeEncrypt(selectedRecipients, parts)

		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()

			_, wErr := writer.Write([]byte(encryptedData))
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
		widget.NewLabel("Recipients:"),
		recipientsButton,
		widget.NewSeparator(),
		widget.NewLabel("Message Parts:"),
		messageList,
		widget.NewButton("Add More Text", func() { addMessageBox() }),
		widget.NewButton("Encrypt & Save", encryptAndSave),
	)
}

func fakeEncrypt(recipients []string, messages []string) string {
	return fmt.Sprintf("Encrypted for: %s\nMessages: %s", strings.Join(recipients, ", "), strings.Join(messages, " | "))
}
