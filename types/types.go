package types

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

type KeyConfig struct {
	PrivateKeys  string `json:"privateKeysDir"`
	ExternalKeys string `json:"externalKeysDir"`
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
