package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"example.com/zerocat/pkg/auth"
	gt "example.com/zerocat/pkg/auth/group-theory"
)

func main() {
	public := flag.Bool("public", false, "generate public key constants")
	private := flag.Bool("private", false, "generate private key constants")
	k := flag.Int("k", 32, "the number of elements in the keys")
	size := flag.Int("size", 3072, "the size of the group to use for proofs")
	key_path := flag.String("path", "./auth.keys", "location for the generated key file")

	flag.Parse()

	var key_file *os.File

	if _, err := os.Stat(*key_path); err == nil {
		// file exists
		key_file, err = os.Open(*key_path)
		defer key_file.Close()

		if err != nil {
			panic(err)
		}

	} else if errors.Is(err, os.ErrNotExist) {
		// file does not exist
		group := gt.SetupCompGroup(*size)
		public_key, private_key, err := auth.FFSKeyPair(*k, group)

		if err != nil {
			panic(err)
		}

		key_file, err = os.Create(*key_path)
		defer key_file.Close()

		if err != nil {
			panic(err)
		}

		public_key_bytes := make([]byte, 0)
		private_key_bytes := make([]byte, 0)
		for i := 0; i < len(public_key); i++ {
			temp_pub := make([]byte, (*size)/8)
			temp_priv := make([]byte, (*size)/8)
			public_key_bytes = append(public_key_bytes, public_key[i].FillBytes(temp_pub)...)
			private_key_bytes = append(private_key_bytes, private_key[i].FillBytes(temp_priv)...)
		}

		modulus_bytes := make([]byte, (*size)/8)
		modulus_bytes = group.Modulus().FillBytes(modulus_bytes)

		headers := make(map[string]string)
		headers["k"] = strconv.Itoa(*k)
		headers["size"] = strconv.Itoa(*size)

		public_block := pem.Block{Type: "FFS PUBLIC KEY", Headers: headers, Bytes: public_key_bytes}
		private_block := pem.Block{Type: "FFS PRIVATE KEY", Headers: headers, Bytes: private_key_bytes}
		modulus_block := pem.Block{Type: "FFS MODULUS", Headers: nil, Bytes: modulus_bytes}

		pem.Encode(key_file, &public_block)
		pem.Encode(key_file, &private_block)
		pem.Encode(key_file, &modulus_block)

		key_file.Seek(0, 0)
	}

	if *public || *private {
		key_bytes, err := io.ReadAll(key_file)

		if err != nil {
			panic(err)
		}

		public_block_decoded, key_bytes := pem.Decode(key_bytes)
		private_block_decoded, key_bytes := pem.Decode(key_bytes)
		modulus_block_decoded, key_bytes := pem.Decode(key_bytes)
		fmt.Println("const", "(")
		if *public {
			fmt.Print("\t", "k int = ", public_block_decoded.Headers["k"], "\n")
			fmt.Print("\t", "size int = ", public_block_decoded.Headers["size"], "\n")
			fmt.Print("\t", "public string = \"", base64.StdEncoding.EncodeToString(public_block_decoded.Bytes), "\"", "\n")
			fmt.Print("\t", "modulus string = \"", base64.StdEncoding.EncodeToString(modulus_block_decoded.Bytes), "\"", "\n")
		} else if *private {
			fmt.Print("\t", "k int = ", private_block_decoded.Headers["k"], "\n")
			fmt.Print("\t", "size int = ", private_block_decoded.Headers["size"], "\n")
			fmt.Print("\t", "private string = \"", base64.StdEncoding.EncodeToString(private_block_decoded.Bytes), "\"", "\n")
			fmt.Print("\t", "modulus string = \"", base64.StdEncoding.EncodeToString(modulus_block_decoded.Bytes), "\"", "\n")
		}
		fmt.Println(")")
	}

}
