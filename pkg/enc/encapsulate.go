package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// the heart of the Key Encapsulation Mechanism, this generates a cryptographically secure random number
// and uses it to derive a key returning the material that encapsulates the key and the encrypted plaintext
type Encapsulator interface {
	Encapsulate([]byte) ([]byte, []byte, []byte, error)
	Decrypt([]byte, []byte, []byte) ([]byte, error)
}

// An encapsulator that utilizes AES for encryption
type AESEncapsulator struct {
	deriver Deriver
}

// Constructor for AES key encapsulator, takes in any type of key derivation function
func NewAESEncapsulator(deriver Deriver) *AESEncapsulator {
	encapsulator := new(AESEncapsulator)
	encapsulator.deriver = deriver

	return encapsulator
}

// takes plaintext and outputs ciphertext along with material encapsulating the key
func (encapsulator *AESEncapsulator) Encapsulate(plaintext []byte) ([]byte, []byte, []byte, error) {
	randomness := make([]byte, 32)
	_, err := rand.Read(randomness)

	if err != nil {
		return nil, nil, nil, err
	}

	key := encapsulator.deriver.Derive(randomness)

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, nil, nil, err
	}

	stream, err := cipher.NewGCM(block)

	if err != nil {
		return nil, nil, nil, err
	}

	nonce := make([]byte, stream.NonceSize())
	_, err = rand.Read(nonce)

	if err != nil {
		return nil, nil, nil, err
	}

	ciphertext := stream.Seal(plaintext[:0], nonce, plaintext, nil)

	return ciphertext, randomness, nonce, nil
}

// takes ciphertext and key material to decrypt the message
func (encapsulator *AESEncapsulator) Decrypt(ciphertext []byte, capsule []byte, nonce []byte) ([]byte, error) {
	key := encapsulator.deriver.Derive(capsule)

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	stream, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	plaintext, err := stream.Open(ciphertext[:0], nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
