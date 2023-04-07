package comm

import (
	"io"

	"example.com/zerocat/pkg/enc"
)

// this wrapper uses KEM to encrypt proofs
type EncapsulationWrapper struct {
	encapsulator *enc.AESEncapsulator
	input        io.Reader
}

// constructs a new encapsulation wrapper
func NewEncapsulationWrapper(encapsulator *enc.AESEncapsulator, input io.Reader) *EncapsulationWrapper {
	wrapper := new(EncapsulationWrapper)
	wrapper.encapsulator = encapsulator
	wrapper.input = input

	return wrapper
}

// wraps the proof in an encryption and appends the key material that encapsulates the key
func (wrapper *EncapsulationWrapper) Wrap() ([]byte, error) {
	buf, err := io.ReadAll(wrapper.input)

	if err != nil {
		return nil, err
	}

	ciphertext, randomness, nonce, err := wrapper.encapsulator.Encapsulate(buf)

	if err != nil {
		return nil, err
	}

	output := make([]byte, 0)
	output = append(output, nonce...)
	output = append(output, randomness...)
	output = append(output, ciphertext...)

	return output, nil
}