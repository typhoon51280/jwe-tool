package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"syscall"

	"github.com/rs/zerolog/log"
	"go.step.sm/crypto/keyutil"

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

func ReadKey(payload []byte, checkForPassword bool) []byte {
	var err error
	block, _ := pem.Decode(payload)
	if block != nil {
		log.Trace().Msgf("Found PEM Block %s: %+v", block.Type, block.Headers)
		payload = block.Bytes
		if checkForPassword && x509.IsEncryptedPEMBlock(block) {
			log.Trace().Msg("Found Password Protected Block")
			password := ReadPassword()
			if payload, err = x509.DecryptPEMBlock(block, password); err != nil {
				log.Fatal().Err(err).Msg("Decrypt failed")
			}
			log.Debug().Msg("Decrypted PEM Key with success.")
		}
		log.Debug().Msg("Decoded PEM Block with success.")
	}
	return payload
}

func LoadKeyPair(data []byte, checkForPassword bool) (interface{}, interface{}, error) {

	input := ReadKey(data, checkForPassword)

	log.Debug().Msg("Testing for PKCS1PrivateKey ...")
	if privateKey, err := x509.ParsePKCS1PrivateKey(input); err == nil {
		log.Debug().Msg("Found PKCS1PrivateKey")
		return privateKey, privateKey.Public(), nil
	} else {
		log.Trace().Err(err).Send()
	}

	log.Debug().Msg("Testing for PKCS8PrivateKey ...")
	if privateKey, err := x509.ParsePKCS8PrivateKey(input); err == nil {
		log.Debug().Msg("Found PKCS8PrivateKey")
		if publicKey, err2 := keyutil.PublicKey(privateKey); err2 == nil {
			log.Debug().Msg("Extracted PublicKey from PKCS8PrivateKey")
			return privateKey, publicKey, nil
		}
	} else {
		log.Trace().Err(err).Send()
	}

	log.Debug().Msg("Testing for ECPrivateKey ...")
	if privateKey, err := x509.ParseECPrivateKey(input); err == nil {
		log.Debug().Msg("Found ECPrivateKey")
		return privateKey, privateKey.PublicKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	return nil, nil, errors.New("parse error, invalid private key")
}

func LoadPrivateKey(data []byte, checkForPassword bool) (interface{}, error) {
	privateKey, _, err := LoadKeyPair(data, checkForPassword)
	return privateKey, err
}
