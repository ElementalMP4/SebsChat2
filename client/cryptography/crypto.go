package cryptography

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"

	"github.com/cloudflare/circl/kem/hybrid"
)

func Encrypt(msg types.InputMessage) (*types.EncryptedMessage, error) {
	messageKey := make([]byte, 32)
	if _, err := rand.Read(messageKey); err != nil {
		return nil, fmt.Errorf("gen message key: %w", err)
	}

	recipientKeys := make(map[string]*types.HybridPublicKeys)
	for _, recipient := range msg.Recipients {
		contact := utils.GetContact(recipient)
		if contact == nil {
			continue
		}
		recipientKeys[recipient] = &contact.Keys
	}

	encryptedKeys := make(map[string]string)
	keySignatures := make(map[string]string)

	for rid, rkeys := range recipientKeys {
		X25519PubBytes, err := utils.Base64ToBytes(rkeys.X25519Pub)
		if err != nil {
			return nil, fmt.Errorf("decode recipient x25519 public key: %w", err)
		}

		PQKemPubBytes, err := utils.Base64ToBytes(rkeys.PQKemPub)
		if err != nil {
			return nil, fmt.Errorf("decode recipient kyber public key: %w", err)
		}

		ephPub, pqCT, wrapKey, err := HybridEncapsulateForRecipient(X25519PubBytes, PQKemPubBytes)
		if err != nil {
			return nil, fmt.Errorf("encapsulate for recipient %s: %w", rid, err)
		}

		encKey, nonce, err := EncryptWithXChaCha20Poly1305(messageKey, wrapKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt message key for %s: %w", rid, err)
		}

		pkg := append(ephPub, append(pqCT, append(nonce, encKey...)...)...)
		encryptedKeys[rid] = base64.StdEncoding.EncodeToString(pkg)

		senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
		if err != nil {
			return nil, fmt.Errorf("decode sender er25519 private key: %w", err)
		}

		senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
		if err != nil {
			return nil, fmt.Errorf("decode sender mldsa65 private key: %w", err)
		}

		edSig, pqSig, err := HybridSign(pkg, senderEdPrivBytes, senderPQSignPrivBytes)
		if err != nil {
			return nil, fmt.Errorf("sign message key for %s: %w", rid, err)
		}

		keySignatures[rid] = base64.StdEncoding.EncodeToString(append(edSig, pqSig...))
	}

	var encObjects []types.EncryptedMessageObject
	for _, obj := range msg.Objects {
		raw, err := json.Marshal(obj.Content)
		if err != nil {
			return nil, fmt.Errorf("marshal object: %w", err)
		}

		ct, nonce, err := EncryptWithXChaCha20Poly1305(raw, messageKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt object: %w", err)
		}

		senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
		if err != nil {
			return nil, fmt.Errorf("decode sender er25519 private key: %w", err)
		}

		senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
		if err != nil {
			return nil, fmt.Errorf("decode sender mldsa65 private key: %w", err)
		}

		edSig, pqSig, err := HybridSign(ct, senderEdPrivBytes, senderPQSignPrivBytes)
		if err != nil {
			return nil, fmt.Errorf("sign full message: %w", err)
		}

		objSig := append(edSig, pqSig...)
		encObjects = append(encObjects, types.EncryptedMessageObject{
			Type:      obj.Type,
			Content:   utils.BytesToBase64(ct),
			Verify:    utils.BytesToBase64(nonce),
			Signature: utils.BytesToBase64(objSig),
		})
	}

	fullData, err := json.Marshal(msg.Objects)
	if err != nil {
		return nil, fmt.Errorf("marshal for signing: %w", err)
	}

	senderEdPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.EdPriv)
	if err != nil {
		return nil, fmt.Errorf("decode sender er25519 private key: %w", err)
	}

	senderPQSignPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQSignPriv)
	if err != nil {
		return nil, fmt.Errorf("decode sender mldsa65 private key: %w", err)
	}

	edSig, pqSig, err := HybridSign(fullData, senderEdPrivBytes, senderPQSignPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("sign full message: %w", err)
	}

	fullSig := base64.StdEncoding.EncodeToString(append(edSig, pqSig...))
	return &types.EncryptedMessage{
		Signature:     fullSig,
		Objects:       encObjects,
		KeySignatures: keySignatures,
		EncryptedKeys: encryptedKeys,
		Sender:        globals.SelfUser.Name,
	}, nil
}

func Decrypt(enc *types.EncryptedMessage) (*types.DecryptedMessage, error) {
	pkgB64, ok := enc.EncryptedKeys[globals.SelfUser.Name]
	if !ok {
		return nil, fmt.Errorf("no encrypted key for this recipient")
	}
	pkg, err := base64.StdEncoding.DecodeString(pkgB64)
	if err != nil {
		return nil, fmt.Errorf("decode key pkg: %w", err)
	}

	kemScheme := hybrid.Kyber768X25519()
	ephPub := pkg[:32]
	pqCT := pkg[32 : 32+kemScheme.CiphertextSize()]
	nonce := pkg[32+kemScheme.CiphertextSize() : 32+kemScheme.CiphertextSize()+24]
	encKey := pkg[32+kemScheme.CiphertextSize()+24:]

	senderX25519PrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.X25519Priv)
	if err != nil {
		return nil, fmt.Errorf("decode sender er25519 private key: %w", err)
	}

	senderKyberPrivBytes, err := utils.Base64ToBytes(globals.SelfUser.Keys.Private.PQKemPriv)
	if err != nil {
		return nil, fmt.Errorf("decode sender mldsa65 private key: %w", err)
	}

	wrapKey, err := HybridDecapsulateFromSender(ephPub, pqCT, senderX25519PrivBytes, senderKyberPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("decapsulate: %w", err)
	}

	messageKey, err := DecryptWithXChaCha20Poly1305(encKey, wrapKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt msgkey: %w", err)
	}

	var objs []types.MessageObject
	for _, eo := range enc.Objects {
		ct, err := utils.Base64ToBytes(eo.Content)
		if err != nil {
			return nil, fmt.Errorf("decode object: %w", err)
		}

		nonce, err := utils.Base64ToBytes(eo.Verify)
		if err != nil {
			return nil, fmt.Errorf("decode nonce: %w", err)
		}

		plain, err := DecryptWithXChaCha20Poly1305(ct, messageKey, nonce)
		if err != nil {
			return nil, fmt.Errorf("decrypt object: %w", err)
		}

		content := make(map[string]string)
		if err := json.Unmarshal(plain, &content); err != nil {
			return nil, fmt.Errorf("unmarshal object: %w", err)
		}

		objs = append(objs, types.MessageObject{
			Type:    eo.Type,
			Content: content,
		})
	}

	return &types.DecryptedMessage{
		Objects: objs,
		Author:  enc.Sender,
	}, nil
}
