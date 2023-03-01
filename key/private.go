package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPrivateKey(filename string) (interface{}, error) {

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("unable to read private key file: %v", err)
		os.Exit(1)
	}

	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
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
		fmt.Printf("unable to read private key file: %v", err)
		os.Exit(1)
	}

	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	if priv, err0 := x509.ParsePKCS1PrivateKey(input); err0 == nil {
		return priv.Public(), nil
	}

	// if priv, err1 := x509.ParsePKCS8PrivateKey(input); err1 == nil {
	// 	return priv, nil
	// }

	if priv, err2 := x509.ParseECPrivateKey(input); err2 == nil {
		return priv.Public(), nil
	}

	return nil, errors.New("parse error, invalid private key")
}
