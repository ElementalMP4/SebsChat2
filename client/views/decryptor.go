package views

import (
	"encoding/json"
	"io"
	"sebschat/cryptography"
	"sebschat/types"
	"sebschat/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func MessageDecryptorUI(win fyne.Window) fyne.CanvasObject {
	history := container.NewVBox()
	historyScroll := container.NewVScroll(history)
	historyScroll.SetMinSize(fyne.NewSize(0, 200))

	openButton := widget.NewButton("Open .enc File", func() {
		fd := dialog.NewFileOpen(
			func(r fyne.URIReadCloser, err error) {
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
				if r == nil {
					return
				}
				defer r.Close()

				data, err := io.ReadAll(r)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}

				err = decryptMessages(data, history, historyScroll)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
			}, win)

		fd.SetFilter(storage.NewExtensionFileFilter([]string{".enc"}))
		fd.Show()
	})

	header := utils.MakeHeaderLabel("Decrypt a message")

	return container.NewBorder(
		container.NewVBox(header, openButton),
		nil, nil, nil,
		historyScroll,
	)
}

func decryptMessages(data []byte, history *fyne.Container, historyScroll *container.Scroll) error {
	var encryptedMessage types.EncryptedMessage
	err := json.Unmarshal(data, &encryptedMessage)
	if err != nil {
		return err
	}

	decrypted, err := cryptography.Decrypt(encryptedMessage, true)
	if err != nil {
		return err
	}

	messagesToDisplay := []string{}
	author := decrypted.Author
	favouriteColour := "#FFFFFF"

	for _, object := range decrypted.Objects {

		switch object.Type {
		case "text":
			messagesToDisplay = append(messagesToDisplay, object.Content["text"])
		case "metadata":
			favouriteColour = object.Content["favouriteColour"]
		}
	}

	for _, message := range messagesToDisplay {
		history.Add(messageBubble(author, favouriteColour, message))
		historyScroll.ScrollToBottom()
	}

	return nil
}
