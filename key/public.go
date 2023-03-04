package key

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func LoadPublicKey(filename string, kid string) (interface{}, error) {

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read public key file: %v", err)
	}

	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	pub1, err1 := x509.ParsePKIXPublicKey(input)
	if err1 == nil {
		return pub1, nil
	}

	pub2, err2 := x509.ParseCertificate(input)
	if err2 == nil {
		return pub2.PublicKey, nil
	}

	pub3, err3 := LoadJSONWebKey(data, true, kid)
	if err3 == nil {
		return pub3, nil
	}

	pub4, err4 := ReadPublicKey(filename)
	if err4 == nil {
		return pub4, nil
	}

	return nil, fmt.Errorf("%w\n%w\n%w\n%w", err1, err2, err3, err4)
}
