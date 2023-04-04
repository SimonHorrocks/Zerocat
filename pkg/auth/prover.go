package auth

import (
	"io"
	"math/big"
)

// the proof holds the statement and the proof which the verifier will check
type Proof struct {
	statement big.Int
	proof     big.Int
}

// Prover interface acts as a layer, anything written to it can have a proof constructed over it
type Prover interface {
	io.ReadWriter
	ProofGen(randomness big.Int) Proof
}
