package auth_test

import (
	"testing"

	"github.com/SimonHorrocks/Zerocat/pkg/auth"
	grouptheory "github.com/SimonHorrocks/Zerocat/pkg/auth/group-theory"
)

func TestNIZKFFS(t *testing.T) {
	group := grouptheory.SetupCompGroup(3072)
	public, private, err := auth.FFSKeyPair(128, group)

	if err != nil {
		t.Error(err)
	}

	challenger := auth.NewChainChallenger()

	prover := auth.SetupFFSProver(private, challenger, group)
	verifier := auth.SetupFFSVerifier(public, challenger, group.Modulus())

	randomness, _ := group.Random()
	proof := prover.ProofGen(randomness, []byte("Hello World!"))

	if !verifier.Verify(proof, []byte("Hello World!")) {
		t.Fail()
	}
}
