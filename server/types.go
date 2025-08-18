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
	Type      string          `json:"type"`
	Content   string          `json:"content"`
	Verify    string          `json:"verify"`
	Signature HybridSignature `json:"signature"`
}

type HybridSignature struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa65"`
}

type EncryptedKey struct {
	Key       string          `json:"key"`
	Signature HybridSignature `json:"signature"`
}

type EncryptedMessage struct {
	Signature     HybridSignature          `json:"signature"`
	Objects       []EncryptedMessageObject `json:"objects"`
	EncryptedKeys map[string]EncryptedKey  `json:"encryptedKeys"`
	Sender        string                   `json:"sender"`
}

type SendReceipt struct {
	Receipt string   `json:"receipt"`
	SentTo  []string `json:"sentTo"`
}

type JustOneMessage struct {
	Message string `json:"message"`
}
