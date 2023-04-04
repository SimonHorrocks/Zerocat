package auth

import "io"

// verifier layer checks proof using scheme
type Verifier interface {
	io.ReadWriter
	Verify(proof Proof) bool
}
