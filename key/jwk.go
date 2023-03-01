package key

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	jose "github.com/go-jose/go-jose/v3"
)

func LoadJSONWebKey(json []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	if jwk.IsPublic() != pub {
		return nil, errors.New("priv/pub JWK key mismatch")
	}
	return &jwk, nil
}

func LoadJSONWebKeySet(filename string, kid string) []jose.JSONWebKey {
	jwkBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read jwk set file: %v", err)
	}
	var jwkSet jose.JSONWebKeySet
	err = json.Unmarshal(jwkBytes, &jwkSet)
	if err != nil {
		log.Fatalf("unable to decode jwks: %v", err)
	}
	if len(kid) > 0 {
		return jwkSet.Keys
	} else {
		return jwkSet.Key(kid)
	}
}
