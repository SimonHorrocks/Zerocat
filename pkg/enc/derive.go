package enc

import "crypto/sha256"

// the Deriver implements the functionality to produce a unique session key from the encapsulating material provided
type Deriver interface {
	Derive([]byte) []byte
}

// object for a derivation function based on SHA256
type Sha256Deriver struct {
	master []byte
}

// constructor for the Sha256 deriver
func NewSha256Deriver(master []byte) *Sha256Deriver {
	deriver := new(Sha256Deriver)
	deriver.master = master

	return deriver
}

// Derivation method returning a hash: H(capsule||master) where || denotes concatenation
func (deriver *Sha256Deriver) Derive(capsule []byte) []byte {
	key_material := make([]byte, 0)
	key_material = append(key_material, capsule...)
	key_material = append(key_material, deriver.master...)

	hash := sha256.New()
	hash.Write(key_material)

	return hash.Sum(nil)
}
