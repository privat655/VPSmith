package managementstate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	secretKeySize            = 32
	secretFormatVersion byte = 1
)

type SecretMaterial struct{ value []byte }

func newSecretMaterial(value []byte) SecretMaterial {
	copyValue := append([]byte(nil), value...)
	return SecretMaterial{value: copyValue}
}

func (s SecretMaterial) Bytes() []byte    { return append([]byte(nil), s.value...) }
func (s SecretMaterial) String() string   { return "[REDACTED]" }
func (s SecretMaterial) GoString() string { return "managementstate.SecretMaterial([REDACTED])" }
func (s SecretMaterial) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret material cannot be serialized")
}

func encryptSecret(key []byte, id SecretID, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize secret cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize secret gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate secret nonce: %w", err)
	}
	out := make([]byte, 1, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out[0] = secretFormatVersion
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, secretAAD(id))
	return out, nil
}

func decryptSecret(key []byte, id SecretID, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 1 || ciphertext[0] != secretFormatVersion {
		return nil, errors.New("unsupported secret ciphertext format")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize secret cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize secret gcm")
	}
	if len(ciphertext) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid secret ciphertext")
	}
	nonce := ciphertext[1 : 1+gcm.NonceSize()]
	payload := ciphertext[1+gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, payload, secretAAD(id))
	if err != nil {
		return nil, errors.New("secret authentication failed")
	}
	return plaintext, nil
}

func secretAAD(id SecretID) []byte { return []byte("vpsmith-secret:v1:" + string(id)) }
