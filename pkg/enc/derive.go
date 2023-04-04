package enc

import "crypto/sha256"

type Deriver interface {
	Derive([]byte) []byte
}

type Sha256Deriver struct {
	master []byte
}

func NewSha256Deriver(master []byte) *Sha256Deriver {
	deriver := new(Sha256Deriver)
	deriver.master = master

	return deriver
}

func (deriver *Sha256Deriver) Derive(capsule []byte) []byte {
	key_material := make([]byte, 0)
	key_material = append(key_material, capsule...)
	key_material = append(key_material, deriver.master...)

	hash := sha256.New()
	hash.Write(key_material)

	return hash.Sum(nil)
}
