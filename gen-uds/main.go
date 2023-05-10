package main

import (
	"bytes"

	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func kdf(length int, ikm, salt, info []byte) ([]byte, error) {
	hkdf := hkdf.New(sha512.New, ikm, salt, info)
	buf := make([]byte, length)

	if _, err := io.ReadFull(hkdf, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func asymKdf(input []byte) (priv []byte, pub []byte, err error) {
	reader := bytes.NewReader(input)
	pubKey, privKey, err := ed25519.GenerateKey(reader)
	return []byte(privKey), []byte(pubKey), err
}

func main() {
	internalEntropy := make([]byte, sha512.Size) // a.k.a. ikm
	if _, err := rand.Read(internalEntropy); err != nil {
		panic(err)
	}

	externalEntropy := make([]byte, sha512.Size) // a.k.a. salt
	if _, err := rand.Read(externalEntropy); err != nil {
		panic(err)
	}

	udsIdSalt := make([]byte, sha512.Size) // a.k.a. salt
	if _, err := rand.Read(udsIdSalt); err != nil {
		panic(err)
	}

	uds, err := kdf(32, internalEntropy, externalEntropy, []byte("UDS"))
	if err != nil {
		panic(err)
	}

	udsPriv, udsPub, err := asymKdf(uds)
	if err != nil {
		panic(err)
	}

	udsId, err := kdf(20, udsPub, udsIdSalt, []byte("ID"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("UDS: %x\n", uds)
	fmt.Printf("UDS Private: %x\n", udsPriv)
	fmt.Printf("UDS Public: %x\n", udsPub)
	fmt.Printf("UDS_ID: %x\n", udsId)
}
