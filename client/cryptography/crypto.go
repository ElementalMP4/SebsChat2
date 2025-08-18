package cryptography

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sebschat/globals"
	"sebschat/log"
	"sebschat/types"
	"sebschat/utils"

	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/gibson042/canonicaljson-go"
)

func Encrypt(msg types.InputMessage) (*types.EncryptedMessage, error) {
	var (
		err           error
		encryptedKeys map[string]types.EncryptedKey
		messageKey    []byte
		ephPub        []byte
		pqCT          []byte
		wrapKey       []byte
		pkg           []byte
		edSig         []byte
		pqSig         []byte
		raw           []byte
		ct            []byte
		nonce         []byte
	)

	err = log.TimedTask("Generate symmetric key", func() error {
		messageKey = make([]byte, 32)
		if _, err := rand.Read(messageKey); err != nil {
			return fmt.Errorf("gen message key: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	recipientKeys := make(map[string]*types.HybridPublicKeys)
	for _, recipient := range msg.Recipients {
		contact := utils.GetContact(recipient)
		if contact == nil {
			continue
		}
		recipientKeys[recipient] = &contact.Keys
	}

	encryptedKeys = make(map[string]types.EncryptedKey)

	for rid, rkeys := range recipientKeys {
		err = log.TimedTask(fmt.Sprintf("Encapsulate %s key", rid), func() error {
			X25519PubBytes, err := utils.Base64ToBytes(rkeys.X25519Pub)
			if err != nil {
				return fmt.Errorf("decode recipient x25519 public key: %w", err)
			}

			PQKemPubBytes, err := utils.Base64ToBytes(rkeys.PQKemPub)
			if err != nil {
				return fmt.Errorf("decode recipient kyber public key: %w", err)
			}

			ephPub, pqCT, wrapKey, err = HybridEncapsulateForRecipient(X25519PubBytes, PQKemPubBytes)
			if err != nil {
				return fmt.Errorf("encapsulate for recipient %s: %w", rid, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = log.TimedTask(fmt.Sprintf("Encrypt symmetric keys for %s", rid), func() error {
			encKey, nonce, err := EncryptWithXChaCha20Poly1305(messageKey, wrapKey)
			if err != nil {
				return fmt.Errorf("encrypt message key for %s: %w", rid, err)
			}
			pkg = append(ephPub, append(pqCT, append(nonce, encKey...)...)...)
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = log.TimedTask(fmt.Sprintf("Sign symmetric keys for %s", rid), func() error {
			senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
			if err != nil {
				return fmt.Errorf("decode sender er25519 private key: %w", err)
			}

			senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
			if err != nil {
				return fmt.Errorf("decode sender mldsa65 private key: %w", err)
			}

			edSig, pqSig, err = HybridSign(pkg, senderEdPrivBytes, senderPQSignPrivBytes)
			if err != nil {
				return fmt.Errorf("sign message key for %s: %w", rid, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		encryptedKeys[utils.HashString(rid)] = types.EncryptedKey{
			Key: utils.BytesToBase64(pkg),
			Signature: types.HybridSignature{
				Ed25519: utils.BytesToBase64(edSig),
				MLDSA65: utils.BytesToBase64(pqSig),
			},
		}
	}

	var encObjects []types.EncryptedMessageObject
	for _, obj := range msg.Objects {
		raw, err = json.Marshal(obj.Content)
		if err != nil {
			return nil, fmt.Errorf("marshal object: %w", err)
		}

		err = log.TimedTask(fmt.Sprintf("Encrypt %s object", obj.Type), func() error {
			ct, nonce, err = EncryptWithXChaCha20Poly1305(raw, messageKey)
			if err != nil {
				return fmt.Errorf("encrypt object: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = log.TimedTask(fmt.Sprintf("Sign encrypted %s object", obj.Type), func() error {
			senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
			if err != nil {
				return fmt.Errorf("decode sender er25519 private key: %w", err)
			}

			senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
			if err != nil {
				return fmt.Errorf("decode sender mldsa65 private key: %w", err)
			}

			edSig, pqSig, err = HybridSign(ct, senderEdPrivBytes, senderPQSignPrivBytes)
			if err != nil {
				return fmt.Errorf("sign object: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		encObjects = append(encObjects, types.EncryptedMessageObject{
			Type:    obj.Type,
			Content: utils.BytesToBase64(ct),
			Verify:  utils.BytesToBase64(nonce),
			Signature: types.HybridSignature{
				Ed25519: utils.BytesToBase64(edSig),
				MLDSA65: utils.BytesToBase64(pqSig),
			},
		})
	}

	outputObject := types.EncryptedMessage{
		Signature:     types.HybridSignature{},
		Objects:       encObjects,
		EncryptedKeys: encryptedKeys,
		Sender:        utils.HashString(globals.SelfUser.Name),
	}

	err = log.TimedTask("Sign whole message", func() error {
		fullData, err := canonicalize(outputObject)
		if err != nil {
			return fmt.Errorf("marshal for signing: %w", err)
		}

		senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
		if err != nil {
			return fmt.Errorf("decode sender er25519 private key: %w", err)
		}

		senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
		if err != nil {
			return fmt.Errorf("decode sender mldsa65 private key: %w", err)
		}

		edSig, pqSig, err = HybridSign(fullData, senderEdPrivBytes, senderPQSignPrivBytes)
		if err != nil {
			return fmt.Errorf("sign full message: %w", err)
		}

		outputObject.Signature = types.HybridSignature{
			Ed25519: utils.BytesToBase64(edSig),
			MLDSA65: utils.BytesToBase64(pqSig),
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &outputObject, nil
}

func Decrypt(enc *types.EncryptedMessage) (*types.DecryptedMessage, error) {
	var (
		err                   error
		senderEdPubBytes      []byte
		senderPQSignPubBytes  []byte
		ephPub                []byte
		pqCT                  []byte
		nonce                 []byte
		encKey                []byte
		senderX25519PrivBytes []byte
		senderKyberPrivBytes  []byte
		messageKey            []byte
		ct                    []byte
		edSig                 []byte
		pqSig                 []byte
	)

	keyPackage, ok := enc.EncryptedKeys[utils.HashString(globals.SelfUser.Name)]
	if !ok {
		return nil, fmt.Errorf("no encrypted key for this recipient")
	}

	sender := utils.GetContactFromHash(enc.Sender)
	if sender == nil {
		return nil, fmt.Errorf("sender not found in contacts")
	}

	err = log.TimedTask("Decode sender signing keys", func() error {
		senderEdPubBytes, err = utils.Base64ToBytes(sender.Keys.EdPub)
		if err != nil {
			return fmt.Errorf("decode sender ed25519 public key: %w", err)
		}
		senderPQSignPubBytes, err = utils.Base64ToBytes(sender.Keys.PQSignPub)
		if err != nil {
			return fmt.Errorf("decode sender pq sign public key: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = log.TimedTask("Verify message signature", func() error {
		edSigFull, err := utils.Base64ToBytes(enc.Signature.Ed25519)
		if err != nil {
			return fmt.Errorf("decode object ed25519 signature: %w", err)
		}

		pqSigFull, err := utils.Base64ToBytes(enc.Signature.MLDSA65)
		if err != nil {
			return fmt.Errorf("decode object mldsa65 signature: %w", err)
		}

		enc.Signature = types.HybridSignature{}
		fullData, err := canonicalize(enc)
		if err != nil {
			return fmt.Errorf("marshal objects for full signature verification: %w", err)
		}

		okEdFull, okPQFull, err := HybridVerify(fullData, senderEdPubBytes, senderPQSignPubBytes, edSigFull, pqSigFull)
		if err != nil {
			return fmt.Errorf("verify full message: %w", err)
		}
		if !okEdFull || !okPQFull {
			return fmt.Errorf("invalid full message signature (ed25519: %t mldsa65: %t)", okEdFull, okPQFull)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = log.TimedTask("Decode sender keys", func() error {
		pkg, err := utils.Base64ToBytes(keyPackage.Key)
		if err != nil {
			return fmt.Errorf("decode encrypted key: %w", err)
		}

		kemScheme := hybrid.Kyber768X25519()
		ephPub = pkg[:32]
		pqCT = pkg[32 : 32+kemScheme.CiphertextSize()]
		nonce = pkg[32+kemScheme.CiphertextSize() : 32+kemScheme.CiphertextSize()+24]
		encKey = pkg[32+kemScheme.CiphertextSize()+24:]

		senderX25519PrivBytes, err = utils.Base64ToBytes(globals.SelfUser.Keys.Private.X25519Priv)
		if err != nil {
			return fmt.Errorf("decode sender x25519 private key: %w", err)
		}

		senderKyberPrivBytes, err = utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQKemPriv)
		if err != nil {
			return fmt.Errorf("decode sender kyber private key: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = log.TimedTask("Decrypt symmetric key", func() error {
		wrapKey, err := HybridDecapsulateFromSender(ephPub, pqCT, senderX25519PrivBytes, senderKyberPrivBytes)
		if err != nil {
			return fmt.Errorf("decapsulate: %w", err)
		}

		messageKey, err = DecryptWithXChaCha20Poly1305(encKey, wrapKey, nonce)
		if err != nil {
			return fmt.Errorf("decrypt msgkey: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var objs []types.MessageObject
	for _, eo := range enc.Objects {
		err = log.TimedTask("Decode object", func() error {
			ct, err = utils.Base64ToBytes(eo.Content)
			if err != nil {
				return fmt.Errorf("decode object: %w", err)
			}

			nonce, err = utils.Base64ToBytes(eo.Verify)
			if err != nil {
				return fmt.Errorf("decode nonce: %w", err)
			}

			edSig, err = utils.Base64ToBytes(eo.Signature.Ed25519)
			if err != nil {
				return fmt.Errorf("decode object ed25519 signature: %w", err)
			}

			pqSig, err = utils.Base64ToBytes(eo.Signature.MLDSA65)
			if err != nil {
				return fmt.Errorf("decode object mldsa65 signature: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = log.TimedTask("Verify object", func() error {
			okEd, okPQ, err := HybridVerify(ct, senderEdPubBytes, senderPQSignPubBytes, edSig, pqSig)
			if err != nil {
				return fmt.Errorf("verify object: %w", err)
			}
			if !okEd || !okPQ {
				return fmt.Errorf("invalid signature on object (ed25519: %t mldsa65: %t)", okEd, okPQ)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = log.TimedTask("Decrypt object", func() error {
			plain, err := DecryptWithXChaCha20Poly1305(ct, messageKey, nonce)
			if err != nil {
				return fmt.Errorf("decrypt object: %w", err)
			}

			content := make(map[string]string)
			if err := json.Unmarshal(plain, &content); err != nil {
				return fmt.Errorf("unmarshal object: %w", err)
			}

			objs = append(objs, types.MessageObject{
				Type:    eo.Type,
				Content: content,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return &types.DecryptedMessage{
		Objects: objs,
		Author:  sender.Name,
	}, nil
}

func canonicalize(v interface{}) ([]byte, error) {
	return canonicaljson.Marshal(v)
}
