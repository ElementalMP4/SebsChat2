package main

import "fmt"

var (
	WS_CONNECT_OK   string = "CONNECT_OK"
	WS_CHAT_MESSAGE string = "CHAT_MESSAGE"
)

type Config struct {
	Port string
	Bind string
}

func (config Config) GetBindAddress() string {
	return fmt.Sprintf("%s:%s", config.Bind, config.Port)
}

type User struct {
	ID             int
	Username       string
	HashedPassword string
	TOTPSecret     string
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	Username   string `json:"username"`
	TOTPSecret string `json:"totpSecret"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totpCode"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type WebSocketMessage struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

type EncryptedMessageObject struct {
	Type      string `json:"type"`
	Content   string `json:"content"`
	Verify    string `json:"verify"`
	Signature string `json:"signature"`
}

type EncryptedMessage struct {
	Objects          []EncryptedMessageObject `json:"objects"`
	EncryptedKeys    map[string]string        `json:"encryptedKeys"`
	SigningPublicKey string                   `json:"signingPublicKey"`
	Sender           string                   `json:"sender"`
	Receipt          string                   `json:"receipt"`
}

type SendReceipt struct {
	Receipt string   `json:"receipt"`
	SentTo  []string `json:"sentTo"`
}

type JustOneMessage struct {
	Message string `json:"message"`
}
