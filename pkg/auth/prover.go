package auth

import (
	"math/big"
)

// the proof holds the statement and the proof which the verifier will check
type Proof struct {
	statement *big.Int
	proof     *big.Int
}

func (proof *Proof) Proof() *big.Int {
	return proof.proof
}

func (proof *Proof) Statement() *big.Int {
	return proof.statement
}

func NewProof(statement, proof *big.Int) *Proof {
	proof_obj := new(Proof)
	proof_obj.proof = proof
	proof_obj.statement = statement

	return proof_obj
}

type Prover interface {
	ProofGen(*big.Int, []byte) *Proof
}

// the challenger produces a deterministic challenge given a statement
type Challenger interface {
	Update([]byte) // commits latest verified block
	Challenge(*big.Int, []byte) []byte
}
