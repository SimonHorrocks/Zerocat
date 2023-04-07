//go:build private
// +build private

//go:generate go run ../key-gen/key_gen_ffs.go --private --path ../../keys/auth.keys

package main

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"example.com/zerocat/pkg/auth"
	gt "example.com/zerocat/pkg/auth/group-theory"
)

var (
	private_key []*big.Int
	master_key  []byte
	group       *gt.CompositeMulGroup
	prover      *auth.FFSProver
)

func init() {
	private_bytes, err := base64.StdEncoding.DecodeString(private)

	if err != nil {
		panic(err)
	}

	private_key = make([]*big.Int, k)

	for i := 0; i < len(private_key); i++ {
		private_key[i] = big.NewInt(0)
		private_key[i].SetBytes(private_bytes[i*(size/8) : (i+1)*(size/8)])
	}
}

func main() {
	fmt.Println(private_key)
}
