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
	Name string           `json:"name"`
	Keys HybridPublicKeys `json:"keys"`
}

type SelfUser struct {
	Name            string        `json:"name"`
	Server          Server        `json:"server"`
	FavouriteColour string        `json:"favouriteColour"`
	Keys            HybridKeypair `json:"keys"`
}

type Server struct {
	Address string `json:"address"`
	UseTls  bool   `json:"useTls"`
	Token   string `json:"token"`
}

type MessageObject struct {
	Type    string            `json:"type"`
	Content map[string]string `json:"content"`
}

type EncryptedMessageObject struct {
	Type      string `json:"type"`
	Content   string `json:"content"`
	Verify    string `json:"verify"`
	Signature string `json:"signature"`
}

type EncryptedMessage struct {
	Signature     string                   `json:"signature"`
	Objects       []EncryptedMessageObject `json:"objects"`
	KeySignatures map[string]string        `json:"keySignatures"`
	EncryptedKeys map[string]string        `json:"encryptedKeys"`
	Sender        string                   `json:"sender"`
}

type HybridKeypair struct {
	Private HybridPrivateKeys `json:"private"`
	Public  HybridPublicKeys  `json:"public"`
}

// In order:
// X25519 (classical)
// Kyber-768 KEM (PQ)
// Ed25519 (classical signing)
// ML-DSA-65 (PQ signing via CIRCL)

type HybridPrivateKeys struct {
	X25519Priv string `json:"x25519_priv"`
	PQKemPriv  string `json:"kyber768_priv"`
	EdPriv     string `json:"ed25519_priv"`
	PQSignPriv string `json:"mldsa65_priv"`
}

type HybridPublicKeys struct {
	X25519Pub string `json:"x25519_pub"`
	PQKemPub  string `json:"kyber768_pub"`
	EdPub     string `json:"ed25519_pub"`
	PQSignPub string `json:"mldsa65_pub"`
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
	From string           `json:"from"`
	Keys HybridPublicKeys `json:"keys"`
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
