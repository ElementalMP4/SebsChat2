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

var (
	wsConn              *websocket.Conn
	connMutex           sync.Mutex
	stopReconnect       chan struct{}
	conversationTargets []string
	historyContainer    types.ChatHistoryContainer
)

// Helper function to create a message bubble with bold username and left padding
func messageBubble(username, favouriteColour, message string) fyne.CanvasObject {
	// Default to theme foreground in case of parsing failure
	col := theme.Color(theme.ColorNameForeground)

	// Try to parse favouriteColour hex
	if parsedCol, err := utils.ParseHexColor(favouriteColour); err == nil {
		col = parsedCol
	}

	usernameLabel := canvas.NewText(username, col)
	usernameLabel.Alignment = fyne.TextAlignLeading
	usernameLabel.TextStyle = fyne.TextStyle{Bold: true}
	usernameLabel.TextSize = 20

	bottomPaddingSize := float32(10)
	bottomPaddingBox := canvas.NewRectangle(nil)
	bottomPaddingBox.SetMinSize(fyne.NewSize(0, bottomPaddingSize))

	messageLabel := canvas.NewText(message, theme.Color(theme.ColorNameForeground))
	messageLabel.Alignment = fyne.TextAlignLeading

	content := container.NewVBox(
		usernameLabel,
		messageLabel,
		bottomPaddingBox,
	)

	leftPaddingSize := float32(10)
	leftPaddingBox := canvas.NewRectangle(nil)
	leftPaddingBox.SetMinSize(fyne.NewSize(leftPaddingSize, 0))

	return container.NewHBox(
		leftPaddingBox,
		content,
	)
}

func ChatUI(win fyne.Window) fyne.CanvasObject {
	contacts := utils.GetContactNames()

	history := container.NewVBox()
	historyScroll := container.NewVScroll(history)

	historyContainer = types.ChatHistoryContainer{
		History:       history,
		HistoryScroll: historyScroll,
	}

	messageEntry := widget.NewEntry()
	messageEntry.SetPlaceHolder("Select a contact to start chatting...")
	messageEntry.Disable()

	connectWebSocket := func() {
		connMutex.Lock()
		if wsConn != nil {
			connMutex.Unlock()
			log.Println("WebSocket is already connected; skipping reconnect")
			return
		}
		connMutex.Unlock()

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

				if globals.SelfUser.Server.Token == "" {
					dialog.ShowError(fmt.Errorf("you are not logged in! Head to account first to authenticate with the server"), win)
					return
				}

				headers := http.Header{}
				headers.Set("Sec-WebSocket-Protocol", "Bearer "+globals.SelfUser.Server.Token)

				log.Println("Connecting to", u.String())
				c, r, err := websocket.DefaultDialer.Dial(u.String(), headers)

				if r.StatusCode == 401 {
					dialog.ShowError(fmt.Errorf("your login token has expired or is invalid. Head to account to re-authenticate with the server"), win)
					return
				}

				if err != nil {
					log.Printf("WebSocket dial failed: %v", err)
					time.Sleep(3 * time.Second)
					continue
				}

				connMutex.Lock()
				wsConn = c
				connMutex.Unlock()

				log.Println("WebSocket connected")

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
							continue
						}

						decrypted, err := cryptography.Decrypt(encryptedMessage, true)
						if err != nil {
							dialog.ShowError(fmt.Errorf("error decrypting message: %v", err), win)
							continue
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
							historyContainer.History.Add(messageBubble(author, favouriteColour, message))
							historyContainer.HistoryScroll.ScrollToBottom()
						}
					}
				}

				// Handle disconnect
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

		contentMap := map[string]string{
			"text": text,
		}

		metadataMap := map[string]string{
			"favouriteColour": globals.SelfUser.FavouriteColour,
		}

		inputMessage := types.InputMessage{
			Recipients: conversationTargets,
			Objects: []types.MessageObject{
				{
					Type:    "text",
					Content: contentMap,
				},
				{
					Type:    "metadata",
					Content: metadataMap,
				},
			},
		}

		encrypted, err := cryptography.Encrypt(inputMessage, true)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error encrypting message: %v", err), win)
			return
		}

		err = utils.SendEncryptedMessage(encrypted)
		if err != nil {
			dialog.ShowError(fmt.Errorf("error sending message: %v", err), win)
			return
		}

		historyContainer.History.Add(messageBubble("You", globals.SelfUser.FavouriteColour, text))
		messageEntry.SetText("")
		historyContainer.HistoryScroll.ScrollToBottom()
	}

	bottomBar := container.NewBorder(nil, nil, nil, nil, messageEntry)
	chatArea := container.NewBorder(nil, bottomBar, nil, nil, historyContainer.HistoryScroll)

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
			historyContainer.History.Objects = nil
			historyContainer.History.Refresh()
			historyContainer.HistoryScroll.ScrollToBottom()

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
