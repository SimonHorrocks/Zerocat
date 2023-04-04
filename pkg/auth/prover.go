package auth

import (
	"math/big"
)

// the proof holds the statement and the proof which the verifier will check
type Proof struct {
	statement *big.Int
	proof     *big.Int
}

type Prover interface {
	ProofGen(*big.Int, []byte) *Proof
}

// the challenger produces a deterministic challenge given a statement
type Challenger interface {
	Update([]byte) // commits latest verified block
	Challenge(*big.Int, []byte) []byte
}
