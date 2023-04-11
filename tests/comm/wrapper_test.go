package comm_test

import (
	"bytes"
	"testing"

	"github.com/SimonHorrocks/Zerocat/pkg/auth"
	gt "github.com/SimonHorrocks/Zerocat/pkg/auth/group-theory"
	"github.com/SimonHorrocks/Zerocat/pkg/comm"
	"github.com/SimonHorrocks/Zerocat/pkg/enc"
)

func TestFFSWrappers(t *testing.T) {
	group := gt.SetupCompGroup(3072)
	public, private, err := auth.FFSKeyPair(128, group)

	if err != nil {
		t.Error(err)
	}

	challenger := auth.NewChainChallenger()

	prover := auth.SetupFFSProver(private, challenger, group)
	verifier := auth.SetupFFSVerifier(public, challenger, group.Modulus())

	deriver := enc.NewSha256Deriver([]byte("secret"))
	encapsulator := enc.NewAESEncapsulator(deriver)

	buffer := new(bytes.Buffer)

	input_wrapper := comm.NewFFSInputWrapper(prover, buffer)
	encapsulation_wrapper := comm.NewEncapsulationWrapper(encapsulator, buffer)
	decryption_wrapper := comm.NewDecryptionWrapper(encapsulator, buffer, 12, 32)
	output_wrapper := comm.NewFFSOutputWrapper(verifier, buffer)

	buffer.Write([]byte("Hello World!!"))

	wrapped, err := input_wrapper.Wrap()

	if err != nil {
		t.Error(err)
	}

	buffer.Write(wrapped)

	wrapped, err = encapsulation_wrapper.Wrap()

	if err != nil {
		t.Error(err)
	}

	buffer.Write(wrapped)

	wrapped, err = decryption_wrapper.Wrap()

	if err != nil {
		t.Error(err)
	}

	buffer.Write(wrapped)

	wrapped, err = output_wrapper.Wrap()

	if err != nil {
		t.Error(err)
	}

	if wrapped[0] != 1 || !bytes.Equal(wrapped[1:], []byte("Hello World!!")) {
		t.Fail()
	}
}
