package crypto

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/rs/zerolog/log"
)

type EncodeOptions struct {
	Algorithm string
	Encoding  string
	Full      bool
	Sign      bool
	Key       interface{}
}

func Encode(payload string, encodeOptions EncodeOptions, signOptions SignOptions) string {

	log.Debug().Msgf("Encode with options: %+v", encodeOptions)

	if encodeOptions.Sign {
		payload = Sign(payload, signOptions)
	}

	alg := jose.KeyAlgorithm(encodeOptions.Algorithm)
	enc := jose.ContentEncryption(encodeOptions.Encoding)
	recpt := jose.Recipient{
		Algorithm: alg,
		Key:       encodeOptions.Key,
	}
	encrypterOptions := jose.EncrypterOptions{}

	crypter, err := jose.NewEncrypter(enc, recpt, &encrypterOptions)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to instantiate encrypter")
	}
	log.Trace().Msgf("Encrypter created: %+v", crypter)

	obj, err := crypter.Encrypt([]byte(payload))
	if err != nil {
		log.Fatal().Err(err).Msg("unable to encrypt")
	}
	log.Trace().Msgf("Encrypting completed: %+v", obj.FullSerialize())

	var encoded string
	if encodeOptions.Full {
		log.Debug().Msg("Full JWT Serialization")
		encoded = obj.FullSerialize()
	} else {
		log.Debug().Msg("Compact JWT Serialization")
		encoded, err = obj.CompactSerialize()
		if err != nil {
			log.Fatal().Err(err).Msg("unable to serialize message")
		}
	}
	log.Info().Msg("JWT encoded with success !!!")
	return encoded
}

func Decode(payload string, encodeOptions EncodeOptions, signOptions SignOptions) string {

	log.Debug().Msgf("Decode with options: %v", encodeOptions)

	encryptedData, err1 := jose.ParseEncrypted(payload)
	if err1 != nil {
		log.Fatal().Err(err1).Msg("Unable to parse payload")
	}
	log.Debug().Msg("Parsed encrypted data")

	data, err2 := encryptedData.Decrypt(encodeOptions.Key)
	if err2 != nil {
		log.Fatal().Err(err2).Msg("Unable to decrypt message")
	}
	plaintext := string(data)
	log.Trace().Msgf("plaintext: %v", plaintext)

	if encodeOptions.Sign {
		Verify(plaintext, signOptions)
	}

	log.Info().Msg("JWT decrypted OK")

	return plaintext
}
