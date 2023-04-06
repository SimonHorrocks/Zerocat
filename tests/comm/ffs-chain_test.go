package comm_test

import (
	"bytes"
	"testing"

	"example.com/zerocat/pkg/auth"
	gt "example.com/zerocat/pkg/auth/group-theory"
	"example.com/zerocat/pkg/comm"
	"example.com/zerocat/pkg/enc"
)

func TestWrappers(t *testing.T) {
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
	encapsulation_wrapper := comm.NewFFSEncapsulationWrapper(encapsulator, buffer, group.Ring().Size()/4)
	decryption_wrapper := comm.NewFFSDecryptionWrapper(encapsulator, buffer, group.Ring().Size()/4, 12, 32)
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
