package key

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/rs/zerolog/log"
	"go.step.sm/crypto/keyutil"
)

type JWKeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
}

func mapKey(jwk jose.JSONWebKey, pub bool) *JWKeyPair {
	if jwk.Valid() && jwk.IsPublic() == pub {
		log.Trace().Msgf("Found valid JSONWebKey [%s]", jwk.KeyID)
		if jwk.IsPublic() {
			return &JWKeyPair{
				PublicKey: jwk.Public().Key,
			}
		}
		return &JWKeyPair{
			PrivateKey: jwk.Key,
			PublicKey:  jwk.Public().Key,
		}
	} else {
		log.Trace().Msgf("jsonWebKey [%s] not valid ", jwk.KeyID)
	}
	return nil
}

func ResolveKeyPair(key interface{}, pub bool, kid string) (interface{}, interface{}, error) {
	if reflect.ValueOf(key).Kind() == reflect.Map {
		keyMap, valid := key.(map[string]JWKeyPair)
		if !valid {
			return nil, nil, errors.New("invalid JsokWebKey")
		}
		if kid != "" {
			log.Trace().Msgf("jsonWebKeySet: %#v", kid)
			if key, ok := keyMap[kid]; ok {
				log.Trace().Msgf("jsonWebKey matched %s", kid)
				return key.PrivateKey, key.PublicKey, nil
			} else {
				return nil, nil, fmt.Errorf("jsonWebKey [%s] not found", kid)
			}
		}
		if len(keyMap) == 0 {
			return nil, nil, errors.New("JsonWebKey empty")
		} else if len(keyMap) > 1 {
			return nil, nil, errors.New("multiple JsonWebKey found")
		}
		var key JWKeyPair
		for _, k := range keyMap {
			key = k
			break
		}
		log.Trace().Msgf("JWKeyPair: %#v", key)
		return key.PrivateKey, key.PublicKey, nil
	} else {
		if pub {
			return nil, key, nil
		}
		if publicKey, err := keyutil.PublicKey(key); err == nil {
			log.Debug().Msg("Extracted PublicKey from PKCS8PrivateKey")
			return key, publicKey, nil
		}
		return key, nil, nil
	}
}

func LoadJSONWebKey(json []byte, pub bool) (map[string]JWKeyPair, error) {
	var jwk jose.JSONWebKey
	var jwkMap = make(map[string]JWKeyPair)

	log.Debug().Msg("Testing for Single JsonWebKey ...")
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		log.Trace().Err(err).Send()
		if jwks, err := LoadJSONWebKeySet(json); err != nil {
			return nil, err
		} else {
			for _, k := range jwks {
				if key := mapKey(k, pub); key != nil {
					jwkMap[k.KeyID] = *key
				}
			}
		}
	} else {
		log.Debug().Msg("Found JsonWebKey")
		if key := mapKey(jwk, pub); key != nil {
			jwkMap[jwk.KeyID] = *key
		}
	}
	return jwkMap, nil
}

func LoadJSONWebKeySet(jwkBytes []byte) ([]jose.JSONWebKey, error) {
	var jwkSet jose.JSONWebKeySet

	log.Debug().Msg("Testing for JsonWebKeySet ...")
	err := json.Unmarshal(jwkBytes, &jwkSet)
	if err != nil {
		log.Trace().Err(err).Send()
		return nil, errors.New("error parsing jwk key set")
	}
	keys := jwkSet.Keys
	if len(keys) > 0 {
		log.Debug().Msg("Found JsonWebKeySet")
		return keys, nil
	} else {
		return nil, errors.New("no keys found in jwk")
	}
}
