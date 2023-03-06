package crypto

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

type EncodeOptions struct {
	Algorithm  string
	Encoding   string
	PrivateKey interface{}
	PublicKey  interface{}
}

func Encode(payload string, encodeOptions EncodeOptions, signOptions SignOptions) (string, jwt.Token) {

	log.Debug().Msgf("Encode with options: %+v", encodeOptions)

	tokenData, token := Sign(payload, signOptions)

	alg := jose.KeyAlgorithm(encodeOptions.Algorithm)
	enc := jose.ContentEncryption(encodeOptions.Encoding)
	recpt := jose.Recipient{
		Algorithm: alg,
		Key:       encodeOptions.PublicKey,
	}
	encrypterOptions := jose.EncrypterOptions{}

	crypter, err := jose.NewEncrypter(enc, recpt, &encrypterOptions)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to instantiate encrypter")
	}
	log.Trace().Msgf("Encrypter created: %+v", crypter)

	obj, err := crypter.Encrypt([]byte(tokenData))
	if err != nil {
		log.Fatal().Err(err).Msg("unable to encrypt")
	}
	log.Trace().Msgf("Encrypting completed: %+v", obj.FullSerialize())

	encodedData, err := obj.CompactSerialize()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to serialize message")
	}
	log.Info().Msg("JWT encoded with success !!!")
	return encodedData, token
}

func Decode(payload string, encodeOptions EncodeOptions, signOptions SignOptions) (string, jwt.Token) {

	log.Debug().Msgf("Decode with options: %#v", encodeOptions)

	encryptedData, err := jose.ParseEncrypted(payload)
	if err != nil {
		log.Fatal().Err(err).Msgf("Unable to parse payload: %s", payload)
	}
	// log.Debug().Msgf("Parsed encrypted data: %#v", encryptedData)

	data, err := encryptedData.Decrypt(encodeOptions.PrivateKey)
	if err != nil {
		log.Fatal().Err(err).Msgf("Unable to decrypt message: %s", payload)
	}
	decryptedData := string(data)
	log.Trace().Msgf("decrypted data: %s", decryptedData)

	token := Verify(decryptedData, signOptions)

	log.Info().Msg("JWT decrypted with success !!!")

	return decryptedData, token
}
