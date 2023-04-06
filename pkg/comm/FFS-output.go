package comm

import (
	"errors"
	"io"
	"math/big"

	"example.com/zerocat/pkg/auth"
)

// this wrapper verifies messages and outputs the result
type FFSOutputWrapper struct {
	verifier *auth.FFSVerifier
	input    io.Reader
}

// constructs a new feige-fiat-shamir output wrapper
func NewFFSOutputWrapper(verifier *auth.FFSVerifier, input io.Reader) *FFSOutputWrapper {
	wrapper := new(FFSOutputWrapper)
	wrapper.verifier = verifier
	wrapper.input = input

	return wrapper
}

// parses the proof and verifies it before outputting the result and message
func (wrapper *FFSOutputWrapper) Wrap() ([]byte, error) {
	message_size := make([]byte, 1)
	_, err := wrapper.input.Read(message_size)

	if err != nil {
		return nil, err
	}

	message := make([]byte, message_size[0])
	n, err := wrapper.input.Read(message)

	if err != nil {
		return nil, err
	}

	if n != int(message_size[0]) {
		return nil, errors.New("Could not read entire message")
	}

	statement_bytes := make([]byte, wrapper.verifier.Modulus().BitLen()/8)
	proof_bytes := make([]byte, wrapper.verifier.Modulus().BitLen()/8)

	n, err = wrapper.input.Read(statement_bytes)

	if err != nil {
		return nil, err
	}

	if n != len(statement_bytes) {
		return nil, errors.New("Could not read entire statement")
	}

	n, err = wrapper.input.Read(proof_bytes)

	if err != nil {
		return nil, err
	}

	if n != len(proof_bytes) {
		return nil, errors.New("Could not read entire proof")
	}

	statement := big.NewInt(0)
	proof := big.NewInt(0)
	statement.SetBytes(statement_bytes)
	proof.SetBytes(proof_bytes)

	proof_obj := auth.NewProof(statement, proof)
	result := wrapper.verifier.Verify(proof_obj, message)

	output := make([]byte, 0)

	if result {
		output = append(output, byte(1))
	} else {
		output = append(output, byte(0))
	}

	output = append(output, message...)

	return output, nil
}
