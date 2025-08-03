package cryptography

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"sebschat/globals"
	"sebschat/log"
	"sebschat/types"
	"sebschat/utils"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func Encrypt(inputMessage types.InputMessage, hashNames bool) (types.EncryptedMessage, error) {
	var (
		senderPriv     []byte
		symKey         []byte
		err            error
		sharedKey      []byte
		encKey         []byte
		encNonce       []byte
		sig            []byte
		userNameOrHash string
	)

	err = log.TimedTask("Load encryption key", func() error {
		senderPriv, err = utils.GetSelfPrivateKey()
		if err != nil {
			return err
		}
		if len(inputMessage.Recipients) == 0 {
			return fmt.Errorf("message has no recipients")
		}
		return nil
	})
	if err != nil {
		return types.EncryptedMessage{}, err
	}

	recipientsWithoutKeys := utils.CheckContactsExist(inputMessage.Recipients)
	if len(recipientsWithoutKeys) > 0 {
		return types.EncryptedMessage{}, fmt.Errorf("recipient key not found for %s", strings.Join(recipientsWithoutKeys, ", "))
	}

	log.TimedTask("Generate symmetric key", func() error {
		symKey = make([]byte, 32)
		rand.Read(symKey)
		return nil
	})

	var messageObjects []types.EncryptedMessageObject

	for _, object := range inputMessage.Objects {
		if object.Content == nil {
			return types.EncryptedMessage{}, fmt.Errorf("object content cannot be empty")
		}
		switch object.Type {
		case "text", "metadata":
			{
				var (
					contentMapBytes []byte
					ciphertext      []byte
					nonce           []byte
				)

				err = log.TimedTask(fmt.Sprintf("Encrypt %s object", object.Type), func() error {
					contentMapBytes, err = json.Marshal(object.Content)
					if err != nil {
						return fmt.Errorf("error encoding message: %v", err)
					}

					ciphertext, nonce, err = encryptSymmetric(contentMapBytes, symKey)
					if err != nil {
						return fmt.Errorf("error encrypting message: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				log.TimedTask(fmt.Sprintf("Sign %s object", object.Type), func() error {
					signingPriv, err := utils.GetSelfSigningPrivateKey()
					if err != nil {
						return err
					}

					sig, err = signMessage(ciphertext, signingPriv)
					if err != nil {
						return fmt.Errorf("error signing message: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.EncryptedMessage{}, err
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
				var (
					bytes         []byte
					encryptedFile []byte
					nonce         []byte
				)

				err = log.TimedTask(fmt.Sprintf("Load file %s", object.Content["fileName"]), func() error {
					file, err := os.Open(object.Content["fileName"])
					if err != nil {
						return fmt.Errorf("failed to open file %s to be encrypted: %w", object.Content, err)
					}
					defer file.Close()

					bytes, err = io.ReadAll(file)
					if err != nil {
						return fmt.Errorf("failed to read file %s to be encrypted: %w", object.Content, err)
					}

					return nil
				})
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				err = log.TimedTask(fmt.Sprintf("Encrypt file %s", object.Content["fileName"]), func() error {
					var fileNamePtr *string
					parts := strings.Split(object.Content["fileName"], "/")
					fileName := parts[len(parts)-1]
					fileNamePtr = &fileName

					contentMap := map[string]string{
						"file":     base64.StdEncoding.EncodeToString(bytes),
						"fileName": *fileNamePtr,
					}

					contentMapBytes, err := json.Marshal(contentMap)
					if err != nil {
						return fmt.Errorf("error encoding message: %v", err)
					}

					encryptedFile, nonce, err = encryptSymmetric(contentMapBytes, symKey)
					if err != nil {
						return fmt.Errorf("error encrypting message: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				err = log.TimedTask(fmt.Sprintf("Sign file %s", object.Content["fileName"]), func() error {
					signingPriv, err := utils.GetSelfSigningPrivateKey()
					if err != nil {
						return err
					}

					sig, err = signMessage(encryptedFile, signingPriv)
					if err != nil {
						return fmt.Errorf("error signing message: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.EncryptedMessage{}, err
				}

				messageObjects = append(messageObjects, types.EncryptedMessageObject{
					Type:      object.Type,
					Content:   base64.StdEncoding.EncodeToString(encryptedFile),
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
	keySignatures := make(map[string]string)

	for _, user := range inputMessage.Recipients {

		err = log.TimedTask(fmt.Sprintf("Derive shared key for %s", user), func() error {
			pub, err := utils.GetContactPublicKey(user)
			if err != nil {
				return err
			}

			sharedKey, err = deriveSharedKey(senderPriv, pub)
			if err != nil {
				return fmt.Errorf("error deriving shared key: %v", err)
			}

			return nil
		})
		if err != nil {
			return types.EncryptedMessage{}, err
		}

		err = log.TimedTask(fmt.Sprintf("Encrypted shared key for %s", user), func() error {
			encKey, encNonce, err = encryptSymmetric(symKey, sharedKey)
			if err != nil {
				return fmt.Errorf("error encrypting symmetric key: %v", err)
			}

			return nil
		})
		if err != nil {
			return types.EncryptedMessage{}, err
		}

		err = log.TimedTask(fmt.Sprintf("Sign shared key for %s", user), func() error {
			userNameOrHash = user
			if hashNames {
				userNameOrHash = utils.HashString(user)
			}

			signingPriv, err := utils.GetSelfSigningPrivateKey()
			if err != nil {
				return err
			}

			keyPayload := append([]byte(userNameOrHash), encNonce...)
			keyPayload = append(keyPayload, encKey...)
			sig, err = signMessage(keyPayload, signingPriv)
			if err != nil {
				return fmt.Errorf("error signing key payload: %v", err)
			}

			return nil
		})
		if err != nil {
			return types.EncryptedMessage{}, err
		}

		encryptedKeys[userNameOrHash] = base64.StdEncoding.EncodeToString(append(encNonce, encKey...))
		keySignatures[userNameOrHash] = base64.StdEncoding.EncodeToString(sig)
	}

	signingPub, err := utils.GetSelfSigningPublicKey()
	if err != nil {
		return types.EncryptedMessage{}, err
	}

	senderNameOrHash := globals.SelfUser.Name
	if hashNames {
		senderNameOrHash = utils.HashString(globals.SelfUser.Name)
	}

	outputMsg := types.EncryptedMessage{
		Objects:          messageObjects,
		EncryptedKeys:    encryptedKeys,
		KeySignatures:    keySignatures,
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPub),
		Sender:           senderNameOrHash,
	}

	err = log.TimedTask("Sign full message", func() error {
		msgToSign := outputMsg
		msgToSign.Signature = ""

		canonicalJSON, err := canonicalize(msgToSign)
		if err != nil {
			return fmt.Errorf("failed to canonicalize message: %v", err)
		}

		signingPriv, err := utils.GetSelfSigningPrivateKey()
		if err != nil {
			return err
		}

		sig = ed25519.Sign(signingPriv, canonicalJSON)
		outputMsg.Signature = base64.StdEncoding.EncodeToString(sig)

		return nil
	})
	if err != nil {
		return types.EncryptedMessage{}, err
	}

	log.LogSuccess("Successfully encrypted!")

	return outputMsg, nil
}

func Decrypt(msg types.EncryptedMessage, namesAreHashed bool) (types.DecryptedMessage, error) {
	msgToVerify := msg
	sigField := msg.Signature
	msgToVerify.Signature = ""

	var (
		err              error
		signingPub       []byte
		sharedKey        []byte
		encKey           []byte
		encNonce         []byte
		symKey           []byte
		nonce            []byte
		ciphertext       []byte
		plaintext        []byte
		fileBytes        []byte
		decryptedFile    []byte
		decryptedObjects []types.MessageObject
		sender           *types.Contact
		content          map[string]string
	)

	err = log.TimedTask("Verify message", func() error {
		canonicalJSON, err := canonicalize(msgToVerify)
		if err != nil {
			return fmt.Errorf("failed to canonicalize message for verification: %v", err)
		}

		overallSignature, err := base64.StdEncoding.DecodeString(sigField)
		if err != nil {
			return fmt.Errorf("invalid message signature encoding: %v", err)
		}

		signingPub, err = base64.StdEncoding.DecodeString(msg.SigningPublicKey)
		if err != nil {
			return fmt.Errorf("invalid signing pubkey: %v", err)
		}

		if !ed25519.Verify(signingPub, canonicalJSON, overallSignature) {
			return fmt.Errorf("message signature verification failed")
		}

		return nil
	})
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	selfUsernameOrHash := globals.SelfUser.Name
	if namesAreHashed {
		selfUsernameOrHash = utils.HashString(globals.SelfUser.Name)
	}

	if len(msg.EncryptedKeys) == 0 {
		return types.DecryptedMessage{}, fmt.Errorf("message contains no keys")
	}

	if _, ok := msg.EncryptedKeys[selfUsernameOrHash]; !ok {
		return types.DecryptedMessage{}, fmt.Errorf("message does not contain key for this user")
	}

	if namesAreHashed {
		sender = utils.GetContactFromHash(msg.Sender)
	} else {
		sender = utils.GetContact(msg.Sender)
	}

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

	err = log.TimedTask("Derive shared key", func() error {
		sharedKey, err = deriveSharedKey(priv, senderPub)
		if err != nil {
			return fmt.Errorf("error deriving shared key: %v", err)
		}

		return nil
	})
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	err = log.TimedTask("Verify shared key", func() error {
		encKeyFull, err := base64.StdEncoding.DecodeString(msg.EncryptedKeys[selfUsernameOrHash])
		if err != nil {
			return fmt.Errorf("error decoding encrypted key: %v", err)
		}
		encNonce = encKeyFull[:chacha20poly1305.NonceSizeX]
		encKey = encKeyFull[chacha20poly1305.NonceSizeX:]

		sig := msg.KeySignatures[selfUsernameOrHash]
		decodedSig, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			return fmt.Errorf("error decoding key signature: %v", err)
		}

		keyPayload := append([]byte(selfUsernameOrHash), encNonce...)
		keyPayload = append(keyPayload, encKey...)

		if !ed25519.Verify(signingPub, keyPayload, decodedSig) {
			return fmt.Errorf("symmetric key signature verification failed")
		}

		return nil
	})
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	err = log.TimedTask("Decrypt shared key", func() error {
		symKey, err = decryptSymmetric(encKey, sharedKey, encNonce)
		if err != nil {
			return fmt.Errorf("error decrypting symmetric key: %v", err)
		}

		return nil
	})
	if err != nil {
		return types.DecryptedMessage{}, err
	}

	for _, object := range msg.Objects {
		if object.Content == "" {
			return types.DecryptedMessage{}, fmt.Errorf("object content cannot be empty")
		}
		switch object.Type {
		case "text", "metadata":
			{

				err = log.TimedTask(fmt.Sprintf("Verify signature for %s object", object.Type), func() error {
					nonce, err = base64.StdEncoding.DecodeString(object.Verify)
					if err != nil {
						return fmt.Errorf("error decoding nonce: %v", err)
					}

					ciphertext, err = base64.StdEncoding.DecodeString(object.Content)
					if err != nil {
						return fmt.Errorf("error decoding ciphertext: %v", err)
					}

					sig, err := base64.StdEncoding.DecodeString(object.Signature)
					if err != nil {
						return fmt.Errorf("error decoding signature: %v", err)
					}

					signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
					if err != nil {
						return fmt.Errorf("error decoding signing public key: %v", err)
					}

					if !ed25519.Verify(signingPub, ciphertext, sig) {
						return fmt.Errorf("signature verification failed")
					}

					return nil
				})
				if err != nil {
					return types.DecryptedMessage{}, err
				}

				err = log.TimedTask(fmt.Sprintf("Decrypted %s object", object.Type), func() error {
					plaintext, err = decryptSymmetric(ciphertext, symKey, nonce)
					if err != nil {
						return fmt.Errorf("error decrypting message: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.DecryptedMessage{}, err
				}

				err = json.Unmarshal(plaintext, &content)
				if err != nil {
					return types.DecryptedMessage{}, fmt.Errorf("failed to decode content: %v", err)
				}

				decryptedObject := types.MessageObject{
					Type:    object.Type,
					Content: content,
				}

				decryptedObjects = append(decryptedObjects, decryptedObject)
			}
		case "file":
			{
				err = log.TimedTask(fmt.Sprintf("Verify signature for %s object", object.Type), func() error {
					nonce, err = base64.StdEncoding.DecodeString(object.Verify)
					if err != nil {
						return fmt.Errorf("error decoding nonce: %v", err)
					}

					fileBytes, err = base64.StdEncoding.DecodeString(object.Content)
					if err != nil {
						return fmt.Errorf("error decoding file: %v", err)
					}

					sig, err := base64.StdEncoding.DecodeString(object.Signature)
					if err != nil {
						return fmt.Errorf("error decoding signature: %v", err)
					}

					signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
					if err != nil {
						return fmt.Errorf("error decoding signing public key: %v", err)
					}

					if !ed25519.Verify(signingPub, fileBytes, sig) {
						return fmt.Errorf("signature verification failed")
					}

					return nil
				})
				if err != nil {
					return types.DecryptedMessage{}, err
				}

				err = log.TimedTask(fmt.Sprintf("Decrypt %s object", object.Type), func() error {
					decryptedFile, err = decryptSymmetric(fileBytes, symKey, nonce)
					if err != nil {
						return fmt.Errorf("error decrypting file: %v", err)
					}

					return nil
				})
				if err != nil {
					return types.DecryptedMessage{}, err
				}

				err = log.TimedTask(fmt.Sprintf("Save file %s", content["fileName"]), func() error {
					err = json.Unmarshal(decryptedFile, &content)
					if err != nil {
						return fmt.Errorf("failed to decode content: %v", err)
					}

					decryptedFileBytes, err := base64.StdEncoding.DecodeString(content["file"])
					if err != nil {
						return fmt.Errorf("error decoding file: %v", err)
					}

					outputPath := fmt.Sprintf("%s/%s", globals.Config.FileStore, content["fileName"])
					err = os.WriteFile(outputPath, decryptedFileBytes, 0600)
					if err != nil {
						return fmt.Errorf("failed to write decrypted file: %w", err)
					}

					return nil
				})
				if err != nil {
					return types.DecryptedMessage{}, err
				}

				outputMap := map[string]string{
					"fileName": content["fileName"],
				}

				decryptedObject := types.MessageObject{
					Type:    object.Type,
					Content: outputMap,
				}

				decryptedObjects = append(decryptedObjects, decryptedObject)
			}
		default:
			{
				return types.DecryptedMessage{}, fmt.Errorf("unsupported message object type: %s", object.Type)
			}
		}
	}

	log.LogSuccess("Successfully decrypted!")

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

func canonicalize(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "")
}
