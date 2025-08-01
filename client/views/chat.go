package views

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"sebschat/cryptography"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/gorilla/websocket"
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

	var (
		wsConn              *websocket.Conn
		connMutex           sync.Mutex // to safely access wsConn
		conversationTargets []string

		stopReconnect chan struct{}
	)

	// Connect and listen with gorilla websocket, auto-reconnect on drop
	connectWebSocket := func() {
		go func() {
			for {
				select {
				case <-stopReconnect:
					return
				default:
				}

				gatewayURL := globals.SelfUser.Server.GetGatewayAddress()
				u, err := url.Parse(gatewayURL)
				if err != nil {
					log.Println("Invalid gateway URL:", err)
					time.Sleep(3 * time.Second)
					continue
				}

				// Prepare headers with Sec-WebSocket-Protocol
				headers := http.Header{}
				headers.Set("Sec-WebSocket-Protocol", "Bearer "+globals.SelfUser.Server.Token)

				log.Println("Connecting to", u.String())
				c, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
				if err != nil {
					log.Println("WebSocket dial failed:", err)
					time.Sleep(3 * time.Second)
					continue
				}

				connMutex.Lock()
				wsConn = c
				connMutex.Unlock()

				log.Println("WebSocket connected")

				// Read loop
				for {
					var msg types.WebSocketMessageContainer
					err := c.ReadJSON(&msg)
					if err != nil {
						log.Println("WebSocket read error:", err)
						break
					}

					switch msg.Type {
					case "CONNECT_OK":
						log.Println("Connected to gateway successfully")
					case "CHAT_MESSAGE":
						var encryptedMessage types.EncryptedMessage
						err = json.Unmarshal(msg.Payload, &encryptedMessage)
						if err != nil {
							dialog.ShowError(fmt.Errorf("error unmarshalling message: %v", err), win)
							return
						}

						decrypted, err := cryptography.Decrypt(encryptedMessage, false)
						if err != nil {
							dialog.ShowError(fmt.Errorf("error decrypting message: %v", err), win)
							return
						}

						for _, object := range decrypted.Objects {
							if object.Type == "text" {
								history.Add(messageBubble(decrypted.Author, *object.Content))
							}
						}
					}
				}

				// Cleanup on disconnect
				connMutex.Lock()
				if wsConn != nil {
					wsConn.Close()
					wsConn = nil
				}
				connMutex.Unlock()

				log.Println("WebSocket disconnected, retrying in 3s...")
				time.Sleep(3 * time.Second)
			}
		}()
	}

	stopReconnect = make(chan struct{})
	connectWebSocket()

	// Send message on Enter key
	messageEntry.OnSubmitted = func(text string) {
		if text == "" || messageEntry.Disabled() {
			return
		}

		connMutex.Lock()
		defer connMutex.Unlock()
		if wsConn == nil {
			log.Println("WebSocket is not connected")
			return
		}

		inputMessage := types.InputMessage{
			Recipients: conversationTargets,
			Objects: []types.MessageObject{
				{
					Type:    "text",
					Content: &text,
				},
			},
		}

		encrypted, err := cryptography.Encrypt(inputMessage, false)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error encrypting message: %v", err), win)
			return
		}

		err = utils.SendEncryptedMessage(encrypted)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error sending message: %v", err), win)
			return
		}

		history.Add(messageBubble("You", text))
		messageEntry.SetText("")
		historyScroll.ScrollToBottom()
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

			// Set current target
			conversationTargets = []string{contactName}
		})
		contactButtons[i] = btn
	}

	contactsList := container.NewVBox(contactButtons...)

	split := container.NewHSplit(contactsList, container.NewStack(chatArea))
	split.Offset = 0.2

	return split
}
