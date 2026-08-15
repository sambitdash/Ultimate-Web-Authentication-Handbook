/*
Chapter-2: Fundamentals of Cryptography
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code takes an input of a password and generates a binhex encoding
of a randomized string using the pbkdf2 function.

Launch the application with the command:
go run ./pbkdf.go password

It produces the result: 1b68bb6371ec338df4c02f0483fe618ff7470f18b78522e41e489182cc6d98b6
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	dk := pbkdf2.Key([]byte(os.Args[1]), []byte("12345678"), 600000, 32, sha256.New)
	encodedString := hex.EncodeToString(dk)
	println(encodedString)
}
