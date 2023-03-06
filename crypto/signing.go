package crypto

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

type SignOptions struct {
	Algorithm  string
	PrivateKey interface{}
	PublicKey  interface{}
	Kid        string
	Duration   string
}

func Sign(payload string, signOptions SignOptions) (string, jwt.Token) {

	log.Debug().Msgf("Signing with options: %#v", signOptions)

	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		log.Fatal().Err(err).Msg("Error during payload unmarshall")
	}
	duration, err := time.ParseDuration(signOptions.Duration)
	if err != nil {
		log.Warn().Msgf("Token duration %s not valid, reset to 1h", signOptions.Duration)
		duration = time.Hour
	}
	now := time.Now()
	nowEpoch := now.Unix()
	claims["iat"] = nowEpoch
	claims["nbf"] = nowEpoch
	claims["exp"] = now.Add(duration).Unix()
	token := jwt.NewWithClaims(jwt.GetSigningMethod(signOptions.Algorithm), claims)
	if signOptions.Kid != "" {
		token.Header["kid"] = signOptions.Kid
	}

	log.Trace().Msgf("Signing token %#v ...", token)

	tokenData, err := token.SignedString(signOptions.PrivateKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Error signing Token")
	}
	log.Info().Msg("Signed Token with success.")

	return tokenData, *token
}

func Verify(payload string, signOptions SignOptions) jwt.Token {

	log.Debug().Msgf("Verify with options: %#v", signOptions)

	token, err := jwt.Parse(payload, func(t *jwt.Token) (interface{}, error) {
		return signOptions.PublicKey, nil
	})
	if err != nil {
		log.Warn().Err(err).Msg("Verification Token failed")
	} else {
		log.Info().Msg("Verified Token with success.")
	}
	return *token
}
