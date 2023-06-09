package grouptheory

import "math/big"

// a multiplicative group of inverses modulo a number
type MultiplicativeGroup interface {
	Ring
	Inverse(*big.Int) *big.Int
}

// a multiplicative group of inverses modulo composite prime modulus n
type CompositeMulGroup struct {
	ring    *ModRing
	totient *big.Int
}

// for the purposes of deserialization, creates a group
// this group will not be able to compute inverses
func NewCompGroup(ring *ModRing) *CompositeMulGroup {
	group := new(CompositeMulGroup)
	group.ring = ring
	group.totient = big.NewInt(0)

	return group
}

// setups a composite multiplicative group
func SetupCompGroup(size int) *CompositeMulGroup {
	group := new(CompositeMulGroup)
	ring, p, q := CompositePrimeRing(size)

	group.ring = ring
	group.totient = big.NewInt(1)

	temp := big.NewInt(0)
	temp.Sub(p, One)
	group.totient.Mul(group.totient, temp)
	temp.Sub(q, One)
	group.totient.Mul(group.totient, temp)

	return group
}

func (compositeGroup *CompositeMulGroup) Ring() *ModRing {
	return compositeGroup.ring
}

// samples a composite multiplicative group
func (compositeGroup *CompositeMulGroup) Random() (*big.Int, error) {
	for {

		if candidate, err := compositeGroup.ring.Random(); err != nil {
			return nil, err
		} else if compositeGroup.In(candidate) {
			return candidate, nil
		}

	}
}

// checks membership of composite modulus group (ensures co-primality)
func (compositeGroup *CompositeMulGroup) In(number *big.Int) bool {
	gcd := big.NewInt(0)
	gcd.GCD(nil, nil, number, compositeGroup.ring.modulus)

	return gcd.Cmp(One) == 0 && compositeGroup.ring.In(number)
}

// computes the multiplicative inverse using euler's theorem
func (compositeGroup *CompositeMulGroup) Inverse(member *big.Int) *big.Int {
	if !compositeGroup.In(member) {
		return nil
	}

	inverse := big.NewInt(0)
	inverse.Sub(compositeGroup.totient, One)
	inverse.Exp(member, inverse, compositeGroup.ring.modulus)

	return inverse
}

func (compositeGroup *CompositeMulGroup) Modulus() *big.Int {
	return compositeGroup.ring.modulus
}

func (compositeGroup *CompositeMulGroup) Mod(number *big.Int) *big.Int {
	return compositeGroup.ring.Mod(number)
}
