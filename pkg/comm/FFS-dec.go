package comm

import (
	"errors"
	"io"

	"example.com/zerocat/pkg/enc"
)

// this wrapper decrypts proofs using the encapsulated key
type FFSDecryptionWrapper struct {
	encapsulator enc.Encapsulator
	input        io.Reader
	FFS_size     int
	nonce_size   int
	capsule_size int
}

// constructs a new decryption wrapper
func NewFFSDecryptionWrapper(encapsulator enc.Encapsulator, input io.Reader, FFS_size, nonce_size, capsule_size int) *FFSDecryptionWrapper {
	wrapper := new(FFSDecryptionWrapper)
	wrapper.encapsulator = encapsulator
	wrapper.input = input
	wrapper.FFS_size = FFS_size
	wrapper.nonce_size = nonce_size
	wrapper.capsule_size = capsule_size

	return wrapper
}

// derives the key and decrypts the message and proof
func (wrapper *FFSDecryptionWrapper) Wrap() ([]byte, error) {
	message_size := make([]byte, 1)
	_, err := wrapper.input.Read(message_size)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, wrapper.nonce_size)
	n, err := wrapper.input.Read(nonce)

	if err != nil {
		return nil, err
	}

	if n != len(nonce) {
		return nil, errors.New("Could not read entire nonce")
	}

	ciphertext := make([]byte, int(message_size[0])+wrapper.FFS_size+16)
	n, err = wrapper.input.Read(ciphertext)

	if err != nil {
		return nil, err
	}

	if n != len(ciphertext) {
		return nil, errors.New("Could not read entire ciphertext")
	}

	capsule := make([]byte, wrapper.capsule_size)
	n, err = wrapper.input.Read(capsule)

	if err != nil {
		return nil, err
	}

	if n != len(capsule) {
		return nil, errors.New("Could not read entire capsule")
	}

	plaintext, err := wrapper.encapsulator.Decrypt(ciphertext, capsule, nonce)

	if err != nil {
		return nil, err
	}

	output := make([]byte, 0)
	output = append(output, message_size...)
	output = append(output, plaintext...)

	return output, nil
}
