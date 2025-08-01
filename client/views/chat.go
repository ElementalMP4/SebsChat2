package views

import (
	"sebschat/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Helper function to create a message bubble with bold username and left padding
func messageBubble(username, message string) fyne.CanvasObject {
	usernameLabel := canvas.NewText(username, theme.Color(theme.ColorNameForeground))
	usernameLabel.Alignment = fyne.TextAlignLeading
	usernameLabel.TextStyle = fyne.TextStyle{Bold: true}
	usernameLabel.TextSize = 20

	bottomPaddingSize := float32(10)
	bottomPaddingBox := canvas.NewRectangle(nil)
	bottomPaddingBox.SetMinSize(fyne.NewSize(0, bottomPaddingSize))

	messageLabel := canvas.NewText(message, theme.Color(theme.ColorNameForeground))
	messageLabel.Alignment = fyne.TextAlignLeading

	// Create the vertical container for message contents
	content := container.NewVBox(
		usernameLabel,
		messageLabel,
		bottomPaddingBox,
	)

	leftPaddingSize := float32(10)
	leftPaddingBox := canvas.NewRectangle(nil)
	leftPaddingBox.SetMinSize(fyne.NewSize(leftPaddingSize, 0))

	return container.NewHBox(
		leftPaddingBox, // left padding spacer
		content,
	)
}

func ChatUI(win fyne.Window) fyne.CanvasObject {
	contacts := utils.GetContactNames()

	history := container.NewVBox()
	historyScroll := container.NewVScroll(history)

	messageEntry := widget.NewEntry()
	messageEntry.SetPlaceHolder("Select a contact to start chatting...")
	messageEntry.Disable()

	// Send message on Enter key
	messageEntry.OnSubmitted = func(text string) {
		if text != "" && !messageEntry.Disabled() {
			history.Add(messageBubble("You", text))
			messageEntry.SetText("")
			historyScroll.ScrollToBottom()
		}
	}

	bottomBar := container.NewBorder(nil, nil, nil, nil, messageEntry)
	chatArea := container.NewBorder(nil, bottomBar, nil, nil, historyScroll)

	var selectedBtn *widget.Button
	contactButtons := make([]fyne.CanvasObject, len(contacts))
	for i, name := range contacts {
		contactName := name // capture range variable
		var btn *widget.Button
		btn = widget.NewButton(contactName, func() {
			// Highlight selected button
			if selectedBtn != nil {
				selectedBtn.Importance = widget.MediumImportance
				selectedBtn.Refresh()
			}
			btn.Importance = widget.HighImportance
			btn.Refresh()
			selectedBtn = btn

			// Enable input
			messageEntry.Enable()
			messageEntry.SetText("")
			messageEntry.SetPlaceHolder("Type a message...")

			// Reset chat history
			history.Objects = nil
			history.Refresh()
			historyScroll.ScrollToBottom()
		})
		contactButtons[i] = btn
	}

	contactsList := container.NewVBox(contactButtons...)

	split := container.NewHSplit(contactsList, container.NewStack(chatArea))
	split.Offset = 0.2

	return split
}
