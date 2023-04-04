package auth

import "math/big"

type FFSProver struct {
	private []big.Int
}

type FFSVerifier struct {
	public []big.Int
}
