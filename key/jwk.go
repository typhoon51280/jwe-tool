package key

import (
	"encoding/json"
	"errors"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/rs/zerolog/log"
)

func LoadJSONWebKey(json []byte, pub bool, kid string) (*jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	var jwk *jose.JSONWebKey

	log.Debug().Msg("Testing for Single JsonWebKey ...")
	err := key.UnmarshalJSON(json)
	if err != nil {
		log.Trace().Err(err).Send()
		jwk, err = LoadJSONWebKeySet(json, kid)
		if err != nil {
			log.Trace().Err(err).Send()
		}
	} else {
		log.Debug().Msg("Found JsonWebKey")
		jwk = &key
	}
	if jwk == nil {
		return nil, errors.New("JWK key parse error")
	}
	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	if jwk.IsPublic() != pub {
		return nil, errors.New("priv/pub JWK key mismatch")
	}
	return jwk, nil
}

func LoadJSONWebKeySet(jwkBytes []byte, kid string) (*jose.JSONWebKey, error) {
	var jwkSet jose.JSONWebKeySet

	log.Debug().Msg("Testing for JsonWebKeySet ...")
	err := json.Unmarshal(jwkBytes, &jwkSet)
	if err != nil {
		log.Trace().Err(err).Send()
		return nil, errors.New("error parsing jwk key set")
	}
	log.Debug().Msg("Found JsonWebKeySet")
	keys := jwkSet.Keys
	if len(kid) > 0 {
		keys = jwkSet.Key(kid)
	}
	if len(keys) > 0 {
		log.Debug().Msgf("Found JsonWebKey for %s", kid)
		return &keys[0], nil
	} else {
		return nil, errors.New("no keys found in jwk")
	}
}
