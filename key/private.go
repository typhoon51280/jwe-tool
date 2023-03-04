package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/typhoon51280/jwe-tool/ioutil"

	"golang.org/x/term"
)

func ReadPassword() []byte {
	fmt.Print("Password: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Panic().Err(err).Send()
	}
	return bytepw
}

func LoadPrivateKey(filename string) (interface{}, error) {

	var err error
	var privateKey interface{}

	data := ioutil.LoadInput(filename)
	input := []byte(data)
	block, _ := pem.Decode(input)
	if block != nil {
		input = block.Bytes
	}

	if x509.IsEncryptedPEMBlock(block) {
		log.Debug().Msg("Found Password Protected Block")
		password := ReadPassword()
		if input, err = x509.DecryptPEMBlock(block, password); err != nil {
			log.Fatal().Err(err).Msg("Decrypt failed")
		}
	}

	if privateKey, err = x509.ParsePKCS1PrivateKey(input); err == nil {
		log.Debug().Msg("Found PKCS1PrivateKey !!!")
		return privateKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(input); err == nil {
		log.Debug().Msg("Found PKCS8PrivateKey !!!")
		return privateKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	if privateKey, err = x509.ParseECPrivateKey(input); err == nil {
		log.Debug().Msg("Found ECPrivateKey !!!")
		return privateKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	return nil, errors.New("parse error, invalid private key")
}
