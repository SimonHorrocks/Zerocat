package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Encapsulator interface {
	Encapsulate([]byte, []byte) ([]byte, []byte, error)
	Decrypt([]byte, []byte, []byte, []byte) error
}

type AESEncapsulator struct {
	deriver Deriver
}

func NewAESEncapsulator(deriver Deriver) *AESEncapsulator {
	encapsulator := new(AESEncapsulator)
	encapsulator.deriver = deriver

	return encapsulator
}

func (encapsulator *AESEncapsulator) Encapsulate(plaintext []byte) ([]byte, []byte, error) {
	randomness := make([]byte, 32)
	_, err := rand.Read(randomness)

	if err != nil {
		return nil, nil, err
	}

	key := encapsulator.deriver.Derive(randomness)

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, nil, err
	}

	stream, err := cipher.NewGCM(block)

	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, stream.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, nil, err
	}

	stream.Seal(nonce, nonce, plaintext, nil)

	return randomness, nonce, nil
}

func (encapsulator *AESEncapsulator) Decrypt(ciphertext []byte, capsule []byte, nonce []byte) error {
	key := encapsulator.deriver.Derive(capsule)

	block, err := aes.NewCipher(key)

	if err != nil {
		return err
	}

	stream, err := cipher.NewGCM(block)

	if err != nil {
		return err
	}

	stream.Open(nil, nonce, ciphertext, nil)

	return nil
}
