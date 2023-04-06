package auth

import (
	"math/big"

	gt "example.com/zerocat/pkg/auth/group-theory"
)

// feige-fiat-shamir prover object
type FFSProver struct {
	private    []*big.Int
	challenger Challenger
	group      *gt.CompositeMulGroup
}

// setup a fiege-fiat-shamir prover object
func SetupFFSProver(private []*big.Int, challenger Challenger, group *gt.CompositeMulGroup) *FFSProver {
	prover := new(FFSProver)
	prover.private = private
	prover.challenger = challenger
	prover.group = group

	return prover
}

func (prover *FFSProver) Group() *gt.CompositeMulGroup {
	return prover.group
}

// generates NIZK proof for feige-fiat-shamir
func (prover *FFSProver) ProofGen(randomness *big.Int, block []byte) *Proof {
	proof := new(Proof)

	// statemenmt =  r**2 mod n
	proof.statement = big.NewInt(0)
	proof.statement.Exp(randomness, gt.Two, prover.group.Modulus())
	// proof (y) = r mod n
	proof.proof = big.NewInt(1)
	proof.proof.Mul(proof.proof, randomness)
	prover.group.Mod(proof.proof)

	challenge := prover.challenger.Challenge(proof.statement, block)
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
	public     []*big.Int
	challenger Challenger
	modulus    *big.Int
}

// setup a fiege-fiat-shamir verifier object
func SetupFFSVerifier(public []*big.Int, challenger Challenger, modulus *big.Int) *FFSVerifier {
	verifier := new(FFSVerifier)
	verifier.public = public
	verifier.challenger = challenger
	verifier.modulus = modulus

	return verifier
}

func (verifier *FFSVerifier) Modulus() *big.Int {
	return verifier.modulus
}

// verifies a NIZK feige-fiat-shamir proof
func (verifier *FFSVerifier) Verify(proof *Proof, block []byte) bool {
	// proof_sqrd (y ** 2)
	proof_sqrd := big.NewInt(0)
	proof_sqrd.Set(proof.proof)
	proof_sqrd.Exp(proof_sqrd, gt.Two, verifier.modulus)

	// verification (z) = statement (x)
	verification := big.NewInt(1)
	verification.Mul(verification, proof.statement)
	verification.Mod(verification, verifier.modulus)

	challenge := verifier.challenger.Challenge(proof.statement, block)
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

func FFSKeyPair(k int, group *gt.CompositeMulGroup) ([]*big.Int, []*big.Int, error) {
	private := make([]*big.Int, 0)
	public := make([]*big.Int, 0)

	for i := 0; i < k; i++ {
		candidate, err := group.Random()

		if err != nil {
			return nil, nil, err
		}

		private = append(private, candidate)

		square := big.NewInt(0)
		square.Exp(candidate, gt.Two, group.Modulus())

		public = append(public, square)
	}

	return public, private, nil
}
