package comm

import (
	"errors"
	"io"

	"example.com/zerocat/pkg/enc"
)

// this wrapper uses KEM to encrypt proofs
type FFSEncapsulationWrapper struct {
	encapsulator enc.Encapsulator
	input        io.Reader
	FFS_size     int
}

// constructs a new encapsulation wrapper
func NewFFSEncapsulationWrapper(encapsulator enc.Encapsulator, input io.Reader, FFS_size int) *FFSEncapsulationWrapper {
	wrapper := new(FFSEncapsulationWrapper)
	wrapper.encapsulator = encapsulator
	wrapper.input = input
	wrapper.FFS_size = FFS_size

	return wrapper
}

// wraps the proof in an encryption and appends the key material that encapsulates the key
func (wrapper *FFSEncapsulationWrapper) Wrap() ([]byte, error) {
	message_size := make([]byte, 1)
	_, err := wrapper.input.Read(message_size)

	if err != nil {
		return nil, err
	}

	buf := make([]byte, int(message_size[0])+wrapper.FFS_size)
	n, err := wrapper.input.Read(buf)

	if err != nil {
		return nil, err
	}

	if n != len(buf) {
		return nil, errors.New("Could not read entire buffer")
	}

	ciphertext, randomness, nonce, err := wrapper.encapsulator.Encapsulate(buf)

	if err != nil {
		return nil, err
	}

	output := make([]byte, 0)
	output = append(output, message_size[0])
	output = append(output, nonce...)
	output = append(output, ciphertext...)
	output = append(output, randomness...)

	if err != nil {
		return nil, err
	}

	return output, nil
}
