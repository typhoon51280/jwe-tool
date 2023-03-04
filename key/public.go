package key

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/rs/zerolog/log"
)

func LoadPublicKey(data []byte, kid string, checkForPassword bool) (interface{}, error) {

	input := []byte(data)
	block, _ := pem.Decode(input)
	if block != nil {
		input = block.Bytes
	}

	log.Debug().Msg("Testing for JsonWebKey ...")
	if jsonWebKey, err := LoadJSONWebKey(input, true, kid); err == nil {
		log.Debug().Msg("Found JsonWebKey")
		return jsonWebKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	log.Debug().Msg("Testing for PKIXPublicKey ...")
	if publicKey, err := x509.ParsePKIXPublicKey(input); err == nil {
		log.Debug().Msg("Found PKIXPublicKey")
		return publicKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	log.Debug().Msg("Testing for Certificate ...")
	if certificate, err := x509.ParseCertificate(input); err == nil {
		log.Debug().Msg("Found PublicKey from Certificate")
		return certificate.PublicKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	log.Debug().Msg("Testing for PrivateKey ...")
	if _, publicKey, err := LoadKeyPair(input, checkForPassword); err == nil {
		log.Debug().Msg("Found PublicKey From PrivateKey")
		return publicKey, nil
	} else {
		log.Trace().Err(err).Send()
	}

	return nil, errors.New("parse error, invalid public key")
}
