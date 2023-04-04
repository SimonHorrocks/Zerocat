package auth

// verifier layer checks proof using scheme
type Verifier interface {
	Verify(Proof, []byte) bool
}
