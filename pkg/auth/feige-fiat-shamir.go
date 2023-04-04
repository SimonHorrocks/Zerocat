package auth

import (
	"bufio"
	"bytes"
	"math/big"

	nt "example.com/zerocat/pkg/auth/number-theory"
)

// feige-fiat-shamir prover object
type FFSProver struct {
	buffer *bufio.ReadWriter

	private    []*big.Int
	challenger Challenger
	group      *nt.CompositeMulGroup
}

// setup a fiege-fiat-shamir prover object
func SetupFFSProver(private []*big.Int, challenger Challenger, group *nt.CompositeMulGroup) *FFSProver {
	prover := new(FFSProver)
	prover.private = private
	prover.challenger = challenger
	stream := make([]byte, ((255*3)+3)*4)
	buf := bytes.NewBuffer(stream)
	reader, writer := bufio.NewReader(buf), bufio.NewWriter(buf)
	prover.buffer = bufio.NewReadWriter(reader, writer)

	return prover
}

// generates NIZK proof for feige-fiat-shamir
func (prover *FFSProver) ProofGen(randomness *big.Int, block []byte) *Proof {
	proof := new(Proof)

	// statemenmt =  r**2 mod n
	proof.statement = big.NewInt(0)
	proof.statement.Exp(randomness, nt.Two, prover.group.Modulus())
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

// writes messages into buffer and appends proofs to them
func (prover *FFSProver) Write(p []byte) (int, error) {
	// TODO: break up messages into chunks of 255 bytes

	for i := 0; i < len(p)/255; i++ {
		block := p[i*255 : (i+1)*255]

		randomness, err := prover.group.Random()

		if err != nil {
			return i * 255, err
		}

		proof := prover.ProofGen(randomness, block) // TODO: check randomness hasn't been used before

		statement_bytes := proof.statement.Bytes()
		proof_bytes := proof.proof.Bytes()

		// writes output = message_size, message, statement_size, statement, proof_size, proof
		output := block[:]

		output = append(output, byte(len(block)))
		output = append(output, p...)
		output = append(output, byte(len(statement_bytes)))
		output = append(output, proof_bytes...)
		output = append(output, byte(len(proof_bytes)))
		output = append(output, proof_bytes...)

		nn, err := prover.buffer.Write(output)

		if err != nil {
			return (i * 255) + nn, err
		}

		prover.challenger.Update(block)
	}

	return len(p), nil
}

// wraps around the buffer object's read
func (prover *FFSProver) Read(p []byte) (int, error) {
	return prover.buffer.Read(p)
}

// feige-fiat-shamir verifier object
type FFSVerifier struct {
	buffer *bufio.ReadWriter

	public     []*big.Int
	challenger Challenger
	modulus    *big.Int
}

// setup a fiege-fiat-shamir verifier object
func SetupFFSVerifier(public []*big.Int, challenger Challenger, group *nt.CompositeMulGroup) *FFSVerifier {
	verifier := new(FFSVerifier)
	verifier.public = public
	verifier.challenger = challenger
	stream := make([]byte, ((255*3)+3)*4)
	buf := bytes.NewBuffer(stream)
	reader, writer := bufio.NewReader(buf), bufio.NewWriter(buf)
	verifier.buffer = bufio.NewReadWriter(reader, writer)

	return verifier
}

// verifies a NIZK feige-fiat-shamir proof
func (verifier *FFSVerifier) Verify(proof *Proof, block []byte) bool {
	// proof_sqrd (y ** 2)
	proof_sqrd := big.NewInt(0)
	proof_sqrd.Set(proof.proof)
	proof_sqrd.Exp(proof_sqrd, nt.Two, verifier.modulus)

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

// wraps around the buffer object's write
func (verifier *FFSVerifier) Write(p []byte) (int, error) {
	return verifier.buffer.Write(p)
}

// reads a single block and proof from the buffer, verifies it and outputs the rseult into p as: verify?, block
func (verifier *FFSVerifier) Read(p []byte) (int, error) {
	block_size, statement_size, proof_size := []byte{0}, []byte{0}, []byte{0}

	verifier.buffer.Read(block_size)
	block := make([]byte, block_size[0])
	verifier.buffer.Read(block)

	verifier.buffer.Read(statement_size)
	statement_bytes := make([]byte, statement_size[0])
	verifier.buffer.Read(statement_bytes)

	verifier.buffer.Read(proof_size)
	proof_bytes := make([]byte, proof_size[0])
	verifier.buffer.Read(proof_bytes)

	statement := big.NewInt(0)
	proof := big.NewInt(0)

	statement.SetBytes(statement_bytes)
	proof.SetBytes(proof_bytes)

	proof_obj := new(Proof)
	proof_obj.statement = statement
	proof_obj.proof = proof

	result := verifier.Verify(proof_obj, block)

	if result {
		p = append(p, byte(1))
		verifier.challenger.Update(block)
	} else {
		p = append(p, byte(0))
	}

	// TODO: check this actually updates the buffer
	p = append(p, block_size...)
	p = append(p, block...)

	return 2 + int(block_size[0]), nil
}
