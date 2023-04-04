package numbertheory

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

// setups a composite multiplicative group
func SetupCompGroup(size int) *CompositeMulGroup {
	group := new(CompositeMulGroup)
	ring, p, q := CompositePrimeRing(size)

	group.ring = ring
	group.totient = big.NewInt(1)

	temp := big.NewInt(0)
	temp.Sub(p, one)
	group.totient.Mul(group.totient, temp)
	temp.Sub(q, one)
	group.totient.Mul(group.totient, temp)

	return group
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

	return gcd.Cmp(one) == 0 && compositeGroup.ring.In(number)
}

// computes the multiplicative inverse using euler's theorem
func (compositeGroup *CompositeMulGroup) Inverse(member *big.Int) *big.Int {
	if !compositeGroup.In(member) {
		return nil
	}

	inverse := big.NewInt(0)
	inverse.Sub(compositeGroup.totient, one)
	inverse.Exp(member, inverse, compositeGroup.ring.modulus)

	return inverse
}
