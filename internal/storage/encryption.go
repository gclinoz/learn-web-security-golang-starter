package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	nonceLength             = 12
	authenticationTagLength = 16
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	return encrypt(plaintext, key, rand.Reader)
}

func encrypt(plaintext []byte, key [32]byte, randomSource io.Reader) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[len(sealed)-authenticationTagLength:],
		Ciphertext: sealed[:len(sealed)-authenticationTagLength],
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != nonceLength || len(payload.AuthTag) != authenticationTagLength {
		return nil, fmt.Errorf("invalid encrypted payload")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	reconstruct := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	reconstruct = append(reconstruct, payload.Ciphertext...)
	reconstruct = append(reconstruct, payload.AuthTag...)
	plaintext, err := aead.Open(nil, payload.Nonce, reconstruct, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
