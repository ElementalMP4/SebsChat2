package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sebschat/globals"
	"sebschat/types"
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

func GetSelfPrivateKey() ([]byte, error) {
	return Base64ToBytes(globals.SelfUser.PrivateKey)
}

func GetSelfPublicKey() ([]byte, error) {
	return Base64ToBytes(globals.SelfUser.PublicKey)
}

func GetSelfSigningPrivateKey() ([]byte, error) {
	return Base64ToBytes(globals.SelfUser.SigningPrivateKey)
}

func GetSelfSigningPublicKey() ([]byte, error) {
	return Base64ToBytes(globals.SelfUser.SigningPublicKey)
}

func GetContactPublicKey(contactName string) ([]byte, error) {
	contact := GetContact(contactName)
	if contact == nil {
		return []byte{}, fmt.Errorf("contact %s not found", contactName)
	}

	return Base64ToBytes(contact.PublicKey)
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
		return contact.Name == contactName
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
