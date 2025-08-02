package types

import (
	"encoding/json"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

type Contacts struct {
	Contacts []Contact `json:"contacts"`
}

type Contact struct {
	Name      string `json:"name"`
	PublicKey string `json:"key"`
}

type SelfUser struct {
	Name              string `json:"name"`
	PublicKey         string `json:"publicKey"`
	PrivateKey        string `json:"privateKey"`
	SigningPublicKey  string `json:"signingPublicKey"`
	SigningPrivateKey string `json:"signingPrivateKey"`
	Server            Server `json:"server"`
}

type Server struct {
	Address string `json:"address"`
	UseTls  bool   `json:"useTls"`
	Token   string `json:"token"`
}

type MessageObject struct {
	Type     string  `json:"type"`
	Content  *string `json:"content,omitempty"`
	FilePath *string `json:"filePath,omitempty"`
}

type EncryptedMessageObject struct {
	Type      string  `json:"type"`
	Content   string  `json:"content"`
	FileName  *string `json:"fileName,omitempty"`
	Verify    string  `json:"verify"`
	Signature string  `json:"signature"`
}

type EncryptedMessage struct {
	Objects          []EncryptedMessageObject `json:"objects"`
	EncryptedKeys    map[string]string        `json:"encryptedKeys"`
	SigningPublicKey string                   `json:"signingPublicKey"`
	Sender           string                   `json:"sender"`
}

type InputMessage struct {
	Objects    []MessageObject `json:"objects"`
	Recipients []string        `json:"recipients"`
}

type Config struct {
	UserFilePath     string `json:"user"`
	ContactsFilePath string `json:"contacts"`
	FileStore        string `json:"files"`
}

type DecryptedMessage struct {
	Objects []MessageObject `json:"object"`
	Author  string          `json:"author"`
}

type KeyExchange struct {
	KeyFrom string `json:"keyFrom"`
	Key     string `json:"key"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totpCode"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	TOTPSecret string `json:"totpSecret"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type WebSocketMessageContainer struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type ChatHistoryContainer struct {
	History       *fyne.Container
	HistoryScroll *container.Scroll
}

func (server Server) GetApiAddress() string {
	protocol := "http"
	if server.UseTls {
		protocol += "s"
	}
	return fmt.Sprintf("%s://%s", protocol, server.Address)
}

func (server Server) GetGatewayAddress() string {
	protocol := "ws"
	if server.UseTls {
		protocol += "s"
	}
	return fmt.Sprintf("%s://%s/gateway", protocol, server.Address)
}
