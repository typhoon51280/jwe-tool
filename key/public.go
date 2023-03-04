package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/rs/zerolog/log"
	"github.com/typhoon51280/jwe-tool/ioutil"
)

func LoadPublicKey(filename string, kid string) (interface{}, error) {

	data := ioutil.LoadInput(filename)
	input := []byte(data)
	block, _ := pem.Decode(input)
	if block != nil {
		input = block.Bytes
	}

	pub1, err1 := x509.ParsePKIXPublicKey(input)
	if err1 == nil {
		return pub1, nil
	} else {
		log.Trace().Err(err1).Send()
	}

	pub2, err2 := x509.ParseCertificate(input)
	if err2 == nil {
		return pub2.PublicKey, nil
	} else {
		log.Trace().Err(err2).Send()
	}

	pub3, err3 := LoadJSONWebKey(input, true, kid)
	if err3 == nil {
		return pub3, nil
	} else {
		log.Trace().Err(err3).Send()
	}

	pub4, err4 := readFromPrivateKey(filename)
	if err4 == nil {
		return pub4, nil
	} else {
		log.Trace().Err(err4).Send()
	}

	return nil, errors.New("parse error, invalid public key")
}

func readFromPrivateKey(filename string) (interface{}, error) {

	data := ioutil.LoadInput(filename)
	input := []byte(data)
	block, _ := pem.Decode(input)
	if block != nil {
		input = block.Bytes
	}

	priv1, err1 := x509.ParsePKCS1PrivateKey(input)
	if err1 == nil {
		return priv1.Public(), nil
	} else {
		log.Trace().Err(err1).Send()
	}

	priv2, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv2.Public(), nil
	} else {
		log.Trace().Err(err2).Send()
	}

	priv3, err3 := x509.ParsePKCS8PrivateKey(input)
	if err3 == nil {
		return priv3, nil
	} else {
		log.Trace().Err(err3).Send()
	}

	return nil, errors.New("error reading public key from private key")
}
