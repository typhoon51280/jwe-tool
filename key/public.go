package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

func LoadPublicKey(filename string) (interface{}, error) {

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read public key file: %v", err)
	}

	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err0 := x509.ParsePKIXPublicKey(input)
	if err0 == nil {
		return pub, nil
	}

	cert, err1 := x509.ParseCertificate(input)
	if err1 == nil {
		return cert.PublicKey, nil
	}

	jwk, err2 := LoadJSONWebKey(data, true)
	if err2 == nil {
		return jwk, nil
	}

	return nil, errors.New("parse error, invalid public key")
}
