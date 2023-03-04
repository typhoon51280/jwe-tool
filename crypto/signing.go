package crypto

import (
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/rs/zerolog/log"
)

type SignOptions struct {
	Algorithm string
	Key       interface{}
	Full      bool
}

func Sign(payload string, signOptions SignOptions) string {

	log.Debug().Msgf("Sign with options: %v", signOptions)

	signKey := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(signOptions.Algorithm),
		Key:       signOptions.Key,
	}
	signerOptions := jose.SignerOptions{
		EmbedJWK: true,
	}
	signer, err := jose.NewSigner(signKey, &signerOptions)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to instantiate signer")
	}
	log.Trace().Msgf("JWT Signer: %v", signer)

	signedPayload, err := signer.Sign([]byte(payload))
	if err != nil {
		log.Fatal().Err(err).Msg("unable to sign")
	}
	log.Trace().Msgf("JWT Signed: %v", signedPayload)

	var serialized string
	if signOptions.Full {
		log.Trace().Msg("Full JWT serialization")
		serialized = signedPayload.FullSerialize()
	} else {
		log.Trace().Msg("Compact JWT serialization")
		if serialized, err = signedPayload.CompactSerialize(); err != nil {
			log.Fatal().Err(err).Msg("unable to serialize message")
		}
	}
	log.Debug().Msg("JWT signed with success !!!")
	return serialized

}

func Verify(payload string, signOptions SignOptions) string {

	log.Debug().Msgf("Verify with options: %v", signOptions)

	jwtSigned, err := jose.ParseSigned(payload)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing jwt")
	}
	log.Trace().Msgf("JWT Signed: %s", jwtSigned.FullSerialize())

	jwtVerified, err := jwtSigned.Verify(signOptions.Key)
	if err != nil {
		log.Fatal().Err(err).Msg("Error verifying jwt")
	}
	plaintext := string(jwtVerified)
	plaintext = strings.Replace(plaintext, "\r", "", -1)
	plaintext = strings.Replace(plaintext, "\n", "", -1)
	log.Trace().Msgf("JWT Verified: %s", plaintext)
	log.Debug().Msg("JWT verified with success !!!")

	return plaintext
}
