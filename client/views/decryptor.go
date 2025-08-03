package views

import (
	"encoding/json"
	"fmt"
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
	output := widget.NewLabel("Decrypted content will appear here...")
	output.Wrapping = fyne.TextWrapWord // Wrap long lines nicely

	openButton := widget.NewButton("Open .enc File", func() {
		fd := dialog.NewFileOpen(
			func(r fyne.URIReadCloser, err error) {
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
				if r == nil {
					return // user canceled
				}
				defer r.Close()

				// Read file
				data, err := io.ReadAll(r)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}

				decrypted, err := decryptToString(data)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
				output.SetText(decrypted)
			}, win)

		fd.SetFilter(
			storage.NewExtensionFileFilter([]string{".enc"}),
		)
		fd.Show()
	})

	return container.NewVBox(utils.MakeHeaderLabel("Decrypt a message"), openButton, output)
}

func decryptToString(data []byte) (string, error) {
	var result types.EncryptedMessage
	var output string
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	decrypted, err := cryptography.Decrypt(result, true)
	if err != nil {
		return "", err
	}

	for _, object := range decrypted.Objects {
		if object.Type == "text" {
			output += fmt.Sprintf("%s: %s\n", decrypted.Author, object.Content["text"])
		}
	}

	return output, nil
}
