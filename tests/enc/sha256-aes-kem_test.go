package enc_test

import (
	"bytes"
	"testing"

	"github.com/SimonHorrocks/Zerocat/pkg/enc"
)

func TestSha256AESKEM(t *testing.T) {
	deriver := enc.NewSha256Deriver([]byte("secret"))
	encapsulator := enc.NewAESEncapsulator(deriver)

	text := []byte("the quick brown fox jumped over the lazy dog")

	text, capsule, nonce, err := encapsulator.Encapsulate(text)

	if err != nil {
		t.Error(err)
	}

	text, err = encapsulator.Decrypt(text, capsule, nonce)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(text, []byte("the quick brown fox jumped over the lazy dog")) {
		t.Fail()
	}
}
