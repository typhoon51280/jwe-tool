package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/term"
)

func ReadPassword() []byte {
	fmt.Print("Password: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	// pass := string(bytepw)
	fmt.Printf("\nYou've entered: %q\n", bytepw)
	return bytepw
}

func LoadPrivateKey(filename string) (interface{}, error) {

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read private key file: %v", err)
	}

	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	if x509.IsEncryptedPEMBlock(block) {
		password := ReadPassword()
		der, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
		input = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	return nil, errors.New("parse error, invalid private key")
}

func ReadPublicKey(filename string) (interface{}, error) {

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read private key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	priv1, err1 := x509.ParsePKCS1PrivateKey(data)
	if err1 == nil {
		return priv1.Public(), nil
	}

	priv2, err2 := x509.ParseECPrivateKey(data)
	if err2 == nil {
		return priv2.Public(), nil
	}

	priv3, err3 := x509.ParsePKCS8PrivateKey(data)
	if err3 == nil {
		return priv3, nil
	}

	return nil, fmt.Errorf("%w\n%w\n%w", err1, err2, err3)
}
