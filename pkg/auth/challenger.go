package auth

import (
	"crypto/sha1"
	"math/big"
)

type ChainChallenger struct {
	chain []byte
}

func NewChainChallenger() *ChainChallenger {
	challenger := new(ChainChallenger)
	challenger.chain = nil

	return challenger
}

func (challenger *ChainChallenger) Challenge(randomness *big.Int, block []byte) []byte {
	image := randomness.Bytes()
	// copy chain and append new block
	chain := make([]byte, len(challenger.chain))
	copy(chain, challenger.chain)
	chain = append(chain, block...)
	// hash chain
	hash := sha1.New()
	hash.Write(chain)
	image = append(image, hash.Sum(nil)...)
	// hash image
	hash.Reset()
	hash.Write(image)

	return hash.Sum(nil)
}

func (challenger *ChainChallenger) Update(block []byte) {
	// append block to chain
	challenger.chain = append(challenger.chain, block...)
	hash := sha1.New()
	// hash chain
	hash.Write(challenger.chain)
	// copy hash to chain
	copy(challenger.chain, hash.Sum(nil))
}
