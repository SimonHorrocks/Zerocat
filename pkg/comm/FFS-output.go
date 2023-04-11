package comm

import (
	"io"
	"math/big"

	"github.com/SimonHorrocks/Zerocat/pkg/auth"
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

	statement_bytes := make([]byte, wrapper.verifier.Modulus().BitLen()/8)
	proof_bytes := make([]byte, wrapper.verifier.Modulus().BitLen()/8)

	_, err := io.ReadFull(wrapper.input, statement_bytes)

	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(wrapper.input, proof_bytes)

	if err != nil {
		return nil, err
	}

	message, err := io.ReadAll(wrapper.input)

	if err != nil {
		return nil, err
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
