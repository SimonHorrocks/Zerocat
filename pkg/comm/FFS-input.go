package comm

import (
	"io"

	"example.com/zerocat/pkg/auth"
)

// this wrapper wraps messages in blocks of 255 bytes into proofs
type FFSInputWrapper struct {
	prover *auth.FFSProver
	input  io.Reader
}

// constructs a new input wrapper for feige-fiat-shamir
func NewFFSInputWrapper(prover *auth.FFSProver, input io.Reader) *FFSInputWrapper {
	wrapper := new(FFSInputWrapper)
	wrapper.prover = prover
	wrapper.input = input

	return wrapper
}

// wraps the message block into a proof and outputs it
func (wrapper *FFSInputWrapper) Wrap() ([]byte, error) {
	buf := make([]byte, 255)
	n, err := wrapper.input.Read(buf)

	if err != nil {
		return nil, err
	} else if n == 0 {
		return nil, nil
	}

	randomness, err := wrapper.prover.Group().Random()

	if err != nil {
		return nil, err
	}

	proof := wrapper.prover.ProofGen(randomness, buf[:n])
	proof_bytes := make([]byte, wrapper.prover.Group().Ring().Size()/8)
	proof_bytes = proof.Proof().FillBytes(proof_bytes)
	statement_bytes := make([]byte, wrapper.prover.Group().Ring().Size()/8)
	statement_bytes = proof.Statement().FillBytes(statement_bytes)
	output := make([]byte, 0)
	output = append(output, byte(n))
	output = append(output, buf[:n]...)
	output = append(output, statement_bytes...)
	output = append(output, proof_bytes...)

	return output, nil
}
