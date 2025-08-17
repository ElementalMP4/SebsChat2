package cryptography

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"sebschat/types"
	"sebschat/utils"

	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func GenerateHybridKeypair() (*types.HybridKeypair, error) {
	xPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, xPriv); err != nil {
		return nil, fmt.Errorf("x25519 rand: %w", err)
	}

	xPub, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 derive pub: %w", err)
	}

	kemScheme := hybrid.Kyber768X25519()
	pkKem, skKem, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("kyber keygen: %w", err)
	}

	pqPub, err := pkKem.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("kyber public key marshal: %w", err)
	}

	pqPriv, err := skKem.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("kyber private key marshal: %w", err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}

	pkPQSign, skPQSign, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ml-dsa keygen: %w", err)
	}
	pqSignPub := pkPQSign.Bytes()
	pqSignPriv := skPQSign.Bytes()

	return &types.HybridKeypair{
		Private: types.HybridPrivateKeys{
			X25519Priv: utils.BytesToBase64(xPriv),
			PQKemPriv:  utils.BytesToBase64(pqPriv),
			EdPriv:     utils.BytesToBase64(edPriv),
			PQSignPriv: utils.BytesToBase64(pqSignPriv),
		},
		Public: types.HybridPublicKeys{
			X25519Pub: utils.BytesToBase64(xPub),
			PQKemPub:  utils.BytesToBase64(pqPub),
			EdPub:     utils.BytesToBase64(edPub),
			PQSignPub: utils.BytesToBase64(pqSignPub),
		},
	}, nil
}

func HybridEncapsulateForRecipient(recipientX25519Pub, recipientPQKemPub []byte) (ephPub, pqCT, wrapKey []byte, err error) {
	ephPriv := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, ephPriv); err != nil {
		return nil, nil, nil, fmt.Errorf("ephemeral x25519 rand: %w", err)
	}
	ephPub, err = curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ephemeral x25519 pub: %w", err)
	}

	ssECDH, err := curve25519.X25519(ephPriv, recipientX25519Pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	kemScheme := hybrid.Kyber768X25519()
	pk, err := kemScheme.UnmarshalBinaryPublicKey(recipientPQKemPub)
	if pk == nil || err != nil {
		return nil, nil, nil, fmt.Errorf("invalid recipient PQ KEM public key: %w", err)
	}

	ct, ssPQ, err := kemScheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kem encapsulate: %w", err)
	}

	concatSS := append(ssECDH, ssPQ...)
	wrapKey, err = HKDFSHA3_256(concatSS, []byte("hybrid-wrap-key"), 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hkdf: %w", err)
	}

	return ephPub, ct, wrapKey, nil
}

func HybridDecapsulateFromSender(ephPub, pqCT, selfX25519Priv, selfPQKemPriv []byte) (wrapKey []byte, err error) {
	ssECDH, err := curve25519.X25519(selfX25519Priv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	kemScheme := hybrid.Kyber768X25519()
	sk, err := kemScheme.UnmarshalBinaryPrivateKey(selfPQKemPriv)
	if sk == nil || err != nil {
		return nil, fmt.Errorf("invalid self PQ KEM private key: %w", err)
	}
	ssPQ, err := kemScheme.Decapsulate(sk, pqCT)
	if err != nil {
		return nil, fmt.Errorf("kem decapsulate: %w", err)
	}

	concatSS := append(ssECDH, ssPQ...)
	wrapKey, err = HKDFSHA3_256(concatSS, []byte("hybrid-wrap-key"), 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return wrapKey, nil
}

func HybridSign(message []byte, edPriv ed25519.PrivateKey, pqSignPriv []byte) (edSig, pqSig []byte, err error) {
	edSig = ed25519.Sign(edPriv, message)
	sk, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(pqSignPriv)
	if sk == nil || err != nil {
		return nil, nil, fmt.Errorf("invalid PQ sign private key: %w", err)
	}

	pqSig, err = sk.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign: %w", err)
	}

	return edSig, pqSig, nil
}

func HybridVerify(message []byte, edPub ed25519.PublicKey, pqSignPub, edSig, pqSig []byte) (bool, bool, error) {
	edOK := ed25519.Verify(edPub, message, edSig)

	pk, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(pqSignPub)
	if pk == nil || err != nil {
		return edOK, false, fmt.Errorf("invalid PQ sign public key %w", err)
	}

	pqScheme := mldsa65.Scheme()
	pqOK := pqScheme.Verify(pk, message, pqSig, nil)
	return edOK, pqOK, nil
}

func HKDFSHA3_256(ikm, info []byte, length int) ([]byte, error) {
	h := func() hash.Hash { return sha3.New256() }
	r := hkdf.New(h, ikm, nil, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	return out, nil
}

func EncryptWithXChaCha20Poly1305(message, key []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, message, nil)
	return ciphertext, nonce, nil
}

func DecryptWithXChaCha20Poly1305(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
