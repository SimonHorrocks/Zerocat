package auth

import (
	"math/big"

	nt "example.com/zerocat/pkg/auth/number-theory"
)

// feige-fiat-shamir prover object
type FFSProver struct {
	private []*big.Int
	group   *nt.CompositeMulGroup
}

// generates NIZK proof for feige-fiat-shamir
func (prover *FFSProver) ProofGen(randomness *big.Int, challenger Challenger) *Proof {
	proof := new(Proof)

	// statemenmt =  r**2 mod n
	proof.statement = big.NewInt(0)
	proof.statement.Exp(randomness, nt.Two, prover.group.Modulus())
	// proof (y) = r mod n
	proof.proof = big.NewInt(1)
	proof.proof.Mul(proof.proof, randomness)
	prover.group.Mod(proof.proof)

	challenge := challenger.Challenge(proof.statement)
	// y = r * sc1 * sc2 * ... sck mod n
	for i := 0; i < len(prover.private); i++ {
		segment := i % 8
		index := i - (segment * 8)
		bit := (challenge[segment] >> byte(index)) & 1

		if bit == 1 {
			proof.proof.Mul(proof.proof, prover.private[i])
			prover.group.Mod(proof.proof)
		}
	}

	return proof
}

// feige-fiat-shamir verifier object
type FFSVerifier struct {
	public  []*big.Int
	modulus *big.Int
}

func (verifier *FFSVerifier) Verify(proof *Proof, challenger Challenger) bool {
	// proof_sqrd (y ** 2)
	proof_sqrd := big.NewInt(0)
	proof_sqrd.Set(proof.proof)
	proof_sqrd.Exp(proof_sqrd, nt.Two, verifier.modulus)

	// verification (z) = statement (x)
	verification := big.NewInt(1)
	verification.Mul(verification, proof.statement)
	verification.Mod(verification, verifier.modulus)

	challenge := challenger.Challenge(proof.statement)
	// z = x * vc1 * vc2 * ... vck mod n
	for i := 0; i < len(verifier.public); i++ {
		segment := i % 8
		index := i - (segment * 8)
		bit := (challenge[segment] >> byte(index)) & 1

		if bit == 1 {
			verification.Mul(verification, verifier.public[i])
			verification.Mod(verification, verifier.modulus)
		}
	}
	// test if z = y ** 2
	return verification.Cmp(proof_sqrd) == 0
}
