package comm

import (
	"encoding/binary"
	"io"

	"github.com/SimonHorrocks/Zerocat/pkg/enc"
)

// this wrapper decrypts proofs using the encapsulated key
type DecryptionWrapper struct {
	encapsulator *enc.AESEncapsulator
	input        io.Reader
	nonce_size   int
	capsule_size int
}

// constructs a new decryption wrapper
func NewDecryptionWrapper(encapsulator *enc.AESEncapsulator, input io.Reader, nonce_size, capsule_size int) *DecryptionWrapper {
	wrapper := new(DecryptionWrapper)
	wrapper.encapsulator = encapsulator
	wrapper.input = input
	wrapper.nonce_size = nonce_size
	wrapper.capsule_size = capsule_size

	return wrapper
}

// derives the key and decrypts the message and proof
func (wrapper *DecryptionWrapper) Wrap() ([]byte, error) {
	nonce := make([]byte, wrapper.nonce_size)
	_, err := io.ReadFull(wrapper.input, nonce)

	if err != nil {
		return nil, err
	}

	capsule := make([]byte, wrapper.capsule_size)
	_, err = io.ReadFull(wrapper.input, capsule)

	if err != nil {
		return nil, err
	}

	ciphertext_size := make([]byte, 4)
	_, err = io.ReadFull(wrapper.input, ciphertext_size)

	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, binary.LittleEndian.Uint32(ciphertext_size))
	_, err = io.ReadFull(wrapper.input, ciphertext)

	if err != nil {
		return nil, err
	}

	plaintext, err := wrapper.encapsulator.Decrypt(ciphertext, capsule, nonce)

	if err != nil {
		return nil, err
	}

	output := make([]byte, 0)
	output = append(output, plaintext...)

	return output, nil
}
