package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"net/http"
	"os"
	"sebschat/globals"
	"sebschat/net"
	"sebschat/types"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
)

func Base64ToBytes(input string) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func BytesToBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func GetContactNames() []string {
	var contacts []string
	for _, contact := range globals.Contacts {
		contacts = append(contacts, contact.Name)
	}
	return contacts
}

func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func GetContactFromHash(hash string) *types.Contact {
	for _, contact := range globals.Contacts {
		if hash == HashString(contact.Name) {
			return &contact
		}
	}
	return nil
}

func ContactExists(contactName string) bool {
	for _, contact := range globals.Contacts {
		if contact.Name == contactName {
			return true
		}
	}
	return false
}

func GetContact(contactName string) *types.Contact {
	for _, contact := range globals.Contacts {
		if contact.Name == contactName {
			return &contact
		}
	}
	return nil
}

func CheckContactsExist(recipients []string) []string {
	var notFound []string
	for _, recipient := range recipients {
		if !ContactExists(recipient) {
			notFound = append(notFound, recipient)
		}
	}
	return notFound
}

func SaveContacts() error {
	contacts := types.Contacts{
		Contacts: globals.Contacts,
	}
	data, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal contacts: %v", err)
	}
	err = os.WriteFile(globals.Config.ContactsFilePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write contacts file: %v", err)
	}
	return nil
}

func SaveUser() error {
	data, err := json.MarshalIndent(globals.SelfUser, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v", err)
	}
	err = os.WriteFile(globals.Config.UserFilePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write user file: %v", err)
	}
	return nil
}

func MessageToJson(input types.EncryptedMessage) ([]byte, error) {
	data, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal message: %v", err)
	}
	return data, nil
}

func ContactToJson() ([]byte, error) {
	kex := types.KeyExchange{
		From: globals.SelfUser.Name,
		Keys: globals.SelfUser.Keys.Public,
	}
	data, err := json.MarshalIndent(kex, "", "  ")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal key exchange: %v", err)
	}
	return data, nil
}

func MakeHeaderLabel(label string) fyne.CanvasObject {
	text := canvas.NewText(label, theme.Color(theme.ColorNameForeground))
	text.Alignment = fyne.TextAlignCenter
	text.TextStyle = fyne.TextStyle{Bold: true}
	text.TextSize = 28

	separator := canvas.NewLine(theme.Color(theme.ColorNameSeparator))
	separator.StrokeWidth = 2

	return container.NewVBox(
		container.NewCenter(text),
		separator,
	)
}

func SendEncryptedMessage(encrypted types.EncryptedMessage) error {
	jsonBody, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to encode request: %v", err)
	}

	req, err := http.NewRequest("POST", globals.SelfUser.Server.GetApiAddress()+"/api/message", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", globals.SelfUser.Server.Token))

	resp, err := net.PerformRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("message was rejected: %s", resp.Status)
	}

	return nil
}

func ParseHexColor(hex string) (color.Color, error) {
	var r, g, b uint8
	if _, err := fmt.Sscanf(hex, "#%02X%02X%02X", &r, &g, &b); err != nil {
		if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err != nil {
			return nil, fmt.Errorf("invalid hex colour: %s", hex)
		}
	}
	return color.NRGBA{R: r, G: g, B: b, A: 255}, nil
}
