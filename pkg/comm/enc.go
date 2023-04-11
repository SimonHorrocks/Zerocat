package comm

import (
	"encoding/binary"
	"io"

	"github.com/SimonHorrocks/Zerocat/pkg/enc"
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
	ciphertext_size := make([]byte, 4)
	binary.LittleEndian.PutUint32(ciphertext_size, uint32(len(ciphertext)))
	output = append(output, ciphertext_size...)
	output = append(output, ciphertext...)

	return output, nil
}
