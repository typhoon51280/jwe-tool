package key

import (
	"encoding/json"
	"errors"

	jose "github.com/go-jose/go-jose/v3"
)

func LoadJSONWebKey(json []byte, pub bool, kid string) (*jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	var jwk *jose.JSONWebKey
	err := key.UnmarshalJSON(json)
	if err != nil {
		jwk, _ = LoadJSONWebKeySet(json, kid)
	} else {
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
	err := json.Unmarshal(jwkBytes, &jwkSet)
	if err != nil {
		return nil, err
	}
	keys := jwkSet.Keys
	if len(kid) > 0 {
		keys = jwkSet.Key(kid)
	}
	if len(keys) > 0 {
		return &keys[0], nil
	} else {
		return nil, errors.New("no keys found in jwk")
	}
}
