package cryptography

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func Encrypt(inputMessage types.InputMessage) (types.EncryptedMessage, error) {
	senderPriv, err := utils.GetSelfPrivateKey()
	if err != nil {
		return types.EncryptedMessage{}, err
	}
	if len(inputMessage.Recipients) == 0 {
		return types.EncryptedMessage{}, fmt.Errorf("message has no recipients")
	}

	recipientsWithoutKeys := utils.CheckContactsExist(inputMessage.Recipients)
	if len(recipientsWithoutKeys) > 0 {
		return types.EncryptedMessage{}, fmt.Errorf("recipient key not found for %s", strings.Join(recipientsWithoutKeys, ", "))
	}

	symKey := make([]byte, 32)
	rand.Read(symKey)

	var messageObjects []types.EncryptedMessageObject

	for _, object := range inputMessage.Objects {
		switch object.Type {
		case "text":
			{
				if object.Content == nil {
					return types.EncryptedMessage{}, fmt.Errorf("text object content cannot be empty")
				}

				if object.FilePath != nil {
					return types.EncryptedMessage{}, fmt.Errorf("text object cannot have a file path")
				}

				ciphertext, nonce, err := encryptSymmetric([]byte(*object.Content), symKey)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("error encrypting message: %v", err)
				}

				signingPriv, err := utils.GetSelfSigningPrivateKey()
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				sig, err := signMessage(ciphertext, signingPriv)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("error signing message: %v", err)
				}

				messageObjects = append(messageObjects, types.EncryptedMessageObject{
					Type:      object.Type,
					Content:   base64.StdEncoding.EncodeToString(ciphertext),
					Verify:    base64.StdEncoding.EncodeToString(nonce),
					Signature: base64.StdEncoding.EncodeToString(sig),
				})
			}
		case "file":
			{
				if object.FilePath == nil {
					return types.EncryptedMessage{}, fmt.Errorf("file object path cannot be empty")
				}

				if object.Content != nil {
					return types.EncryptedMessage{}, fmt.Errorf("file object cannot have content")
				}

				file, err := os.Open(*object.FilePath)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("failed to open file %s to be encrypted: %w", *object.FilePath, err)
				}
				defer file.Close()

				bytes, err := io.ReadAll(file)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("failed to read file %s to be encrypted: %w", *object.FilePath, err)
				}
				encryptedFile, nonce, err := encryptSymmetric(bytes, symKey)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("error encrypting message: %v", err)
				}

				signingPriv, err := utils.GetSelfSigningPrivateKey()
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				sig, err := signMessage(encryptedFile, signingPriv)
				if err != nil {
					return types.EncryptedMessage{}, fmt.Errorf("error signing message: %v", err)
				}

				var fileNamePtr *string
				if object.FilePath != nil {
					parts := strings.Split(*object.FilePath, "/")
					fileName := parts[len(parts)-1]
					fileNamePtr = &fileName
				}

				messageObjects = append(messageObjects, types.EncryptedMessageObject{
					Type:      object.Type,
					Content:   base64.StdEncoding.EncodeToString(encryptedFile),
					FileName:  fileNamePtr,
					Verify:    base64.StdEncoding.EncodeToString(nonce),
					Signature: base64.StdEncoding.EncodeToString(sig),
				})
			}
		default:
			{
				return types.EncryptedMessage{}, fmt.Errorf("unsupported message object type: %s", object.Type)
			}
		}
	}

	encryptedKeys := make(map[string]string)
	for _, user := range inputMessage.Recipients {
		pub, err := utils.GetContactPublicKey(user)
		if err != nil {
			return types.EncryptedMessage{}, err
		}

		sharedKey, err := deriveSharedKey(senderPriv, pub)
		if err != nil {
			return types.EncryptedMessage{}, fmt.Errorf("error deriving shared key: %v", err)
		}
		encKey, encNonce, err := encryptSymmetric(symKey, sharedKey)
		if err != nil {
			return types.EncryptedMessage{}, fmt.Errorf("error encrypting symmetric key: %v", err)
		}
		userHash := utils.HashString(user)

		encryptedKeys[userHash] = base64.StdEncoding.EncodeToString(append(encNonce, encKey...))
	}

	signingPub, err := utils.GetSelfSigningPublicKey()
	if err != nil {
		return types.EncryptedMessage{}, err
	}

	outputMsg := types.EncryptedMessage{
		Objects:          messageObjects,
		EncryptedKeys:    encryptedKeys,
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPub),
		Sender:           utils.HashString(globals.SelfUser.Name),
	}
	return outputMsg, nil
}

func Decrypt(msg types.EncryptedMessage) (types.DecryptedMessage, error) {
	hashedUsername := utils.HashString(globals.SelfUser.Name)
	if msg.Sender == hashedUsername {
		return types.DecryptedMessage{}, fmt.Errorf("cannot decrypt message sent by self")
	}

	if len(msg.EncryptedKeys) == 0 {
		return types.DecryptedMessage{}, fmt.Errorf("message contains no keys")
	}

	if _, ok := msg.EncryptedKeys[hashedUsername]; !ok {
		return types.DecryptedMessage{}, fmt.Errorf("message does not contain key for this user")
	}

	sender := utils.GetContactFromHash(msg.Sender)
	if sender == nil {
		return types.DecryptedMessage{}, fmt.Errorf("sender not found in contacts - %s", strings.Join(utils.GetContactNames(), ", "))
	}

	senderUsername := sender.Name
	priv, err := utils.GetSelfPrivateKey()
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	senderPub, err := utils.GetContactPublicKey(senderUsername)
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	sharedKey, err := deriveSharedKey(priv, senderPub)
	if err != nil {
		return types.DecryptedMessage{}, fmt.Errorf("error deriving shared key: %v", err)
	}

	encKeyFull, err := base64.StdEncoding.DecodeString(msg.EncryptedKeys[hashedUsername])
	if err != nil {
		return types.DecryptedMessage{}, fmt.Errorf("error decoding encrypted key: %v", err)
	}
	encNonce := encKeyFull[:chacha20poly1305.NonceSizeX]
	encKey := encKeyFull[chacha20poly1305.NonceSizeX:]

	symKey, err := decryptSymmetric(encKey, sharedKey, encNonce)
	if err != nil {
		return types.DecryptedMessage{}, fmt.Errorf("error decrypting symmetric key: %v", err)
	}

	var decryptedObjects []types.MessageObject

	for _, object := range msg.Objects {
		switch object.Type {
		case "text":
			{
				if object.Content == "" {
					return types.DecryptedMessage{}, fmt.Errorf("text object content cannot be empty")
				}

				nonce, err := base64.StdEncoding.DecodeString(object.Verify)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding nonce: %v", err)
				}

				ciphertext, err := base64.StdEncoding.DecodeString(object.Content)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding ciphertext: %v", err)
				}

				sig, err := base64.StdEncoding.DecodeString(object.Signature)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding signature: %v", err)
				}

				signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding signing public key: %v", err)
				}

				if !ed25519.Verify(signingPub, ciphertext, sig) {
					return types.DecryptedMessage{}, fmt.Errorf("signature verification failed")
				}

				plaintext, err := decryptSymmetric(ciphertext, symKey, nonce)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decrypting message: %v", err)
				}

				content := string(plaintext)
				decryptedObject := types.MessageObject{
					Type:    object.Type,
					Content: &content,
				}

				decryptedObjects = append(decryptedObjects, decryptedObject)
			}
		case "file":
			{
				if object.FileName == nil {
					return types.DecryptedMessage{}, fmt.Errorf("file object name cannot be empty")
				}

				nonce, err := base64.StdEncoding.DecodeString(object.Verify)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding nonce: %v", err)
				}

				fileBytes, err := base64.StdEncoding.DecodeString(object.Content)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding file: %v", err)
				}

				sig, err := base64.StdEncoding.DecodeString(object.Signature)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding signature: %v", err)
				}

				signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decoding signing public key: %v", err)
				}

				if !ed25519.Verify(signingPub, fileBytes, sig) {
					return types.DecryptedMessage{}, fmt.Errorf("signature verification failed")
				}

				decryptedFile, err := decryptSymmetric(fileBytes, symKey, nonce)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("error decrypting file: %v", err)
				}

				outputPath := fmt.Sprintf("%s/%s", globals.Config.FileStore, *object.FileName)
				err = os.WriteFile(outputPath, decryptedFile, 0600)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("failed to write decrypted file: %w", err)
				}

				decryptedObject := types.MessageObject{
					Type:     object.Type,
					FilePath: &outputPath,
				}

				decryptedObjects = append(decryptedObjects, decryptedObject)
			}
		default:
			{
				return types.DecryptedMessage{}, fmt.Errorf("unsupported message object type: %s", object.Type)
			}
		}
	}

	return types.DecryptedMessage{
		Objects: decryptedObjects,
		Author:  senderUsername,
	}, nil
}

func GenerateX25519KeyPair() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	_, err := rand.Read(priv)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

func deriveSharedKey(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}

func encryptSymmetric(message, key []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, message, nil)
	return ciphertext, nonce, nil
}

func decryptSymmetric(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func signMessage(message []byte, priv []byte) ([]byte, error) {
	return ed25519.Sign(priv, message), nil
}
