package grouptheory

import (
	"crypto/rand"
	"math/big"
)

// some helpful constants
var (
	Zero *big.Int = big.NewInt(0)
	One  *big.Int = big.NewInt(1)
	Two  *big.Int = big.NewInt(2)
)

type Ring interface {
	Random() big.Int
	In(*big.Int) bool
}

type ModRing struct {
	modulus *big.Int
	size    int
}

// sets up a basic ring of numbers modulo any number n
func SetupModRing(modulus *big.Int) *ModRing {
	ring := new(ModRing)
	ring.modulus = modulus
	ring.size = modulus.BitLen()

	return ring
}

// sets up a ring of prime modulus p (all elements therefore co-prime to p)
func PrimeRing(size int) *ModRing {
	if p, err := rand.Prime(rand.Reader, size); err != nil {
		return nil
	} else {
		return SetupModRing(p)
	}
}

// sets up a ring of composite prime modulus (not a multiplicative group yet since no gaurantee of co-prime)
func CompositePrimeRing(size int) (*ModRing, *big.Int, *big.Int) {
	p, err := rand.Prime(rand.Reader, size/2)

	if err != nil {
		return nil, nil, nil
	}

	q, err := rand.Prime(rand.Reader, size/2)

	if err != nil {
		return nil, nil, nil
	}

	n := big.NewInt(0)

	n.Mul(p, q)

	return SetupModRing(n), p, q
}

func (ring *ModRing) Size() int {
	return ring.size
}

// any number is a member of the ring if it is between 0 and the modulus
func (ring *ModRing) In(number *big.Int) bool {
	return number.Cmp(One) > -1 && number.Cmp(ring.modulus) < 0
}

// samples an element from the ring
func (ring *ModRing) Random() (*big.Int, error) {

	for {

		if candidate, err := rand.Int(rand.Reader, ring.modulus); err != nil {
			return nil, err
		} else if ring.In(candidate) {
			return candidate, nil
		}

	}
}

// computes the mod of a number modulo the ring's modulus
func (ring *ModRing) Mod(number *big.Int) *big.Int {
	return number.Mod(number, ring.modulus)
}
