package crypto

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"github.com/typhoon51280/jwe-tool/key"
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

	token, err := jwt.Parse(payload, func(token *jwt.Token) (interface{}, error) {

		_, publicKey, err := key.ResolveKeyPair(signOptions.PublicKey, true, signOptions.Kid)
		if err != nil {
			log.Error().Err(err).Msg("sign key not found")
			return nil, err
		}
		return publicKey, nil

		// if reflect.ValueOf(signOptions.PublicKey).Kind() == reflect.Map {
		// 	keyMap, valid := signOptions.PublicKey.(map[string]interface{})
		// 	if !valid {
		// 		return nil, errors.New("invalid JsokWebKey")
		// 	}
		// 	log.Trace().Msgf("jsonWebKeySet: %#v", keyMap)
		// 	if tokenKid, ok := token.Header["kid"]; ok {
		// 		if signOptions.Kid != "" && signOptions.Kid != tokenKid.(string) {
		// 			return nil, fmt.Errorf("mismatched keys: specified [%s] found [%s]", signOptions.Kid, tokenKid)
		// 		}
		// 	}
		// 	if signOptions.Kid != "" {
		// 		if key, ok := keyMap[signOptions.Kid]; ok {
		// 			log.Trace().Msgf("jsonWebKey matched %s", signOptions.Kid)
		// 			return key, nil
		// 		} else {
		// 			return nil, fmt.Errorf("jsonWebKey [%s] not found", signOptions.Kid)
		// 		}
		// 	}
		// 	if len(keyMap) == 0 {
		// 		return nil, errors.New("JsonWebKey empty")
		// 	} else if len(keyMap) > 1 {
		// 		return nil, errors.New("multiple JsonWebKey found")
		// 	}
		// 	var key interface{}
		// 	for _, k := range keyMap {
		// 		key = k
		// 		break
		// 	}
		// 	return key, nil
		// } else {
		// 	return signOptions.PublicKey, nil
		// }
	})
	if err != nil {
		log.Warn().Err(err).Msg("Verification Token failed")
	} else {
		log.Info().Msg("Verified Token with success.")
	}
	return *token
}
