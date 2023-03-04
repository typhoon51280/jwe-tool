package crypto

import (
	"log"

	"github.com/go-jose/go-jose/v3"
)

func Sign(payload []byte, privateKey interface{}, alg string) string {

	signKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: privateKey}
	signOpts := jose.SignerOptions{EmbedJWK: true}
	signer, err := jose.NewSigner(signKey, &signOpts)
	if err != nil {
		log.Fatalf("Signer not created: %v", err)
	}

	object, err := signer.Sign(payload)
	if err != nil {
		log.Fatalf("Error sign  %v", err)
	}

	serialized, err := object.CompactSerialize()
	if err != nil {
		log.Fatalf("Error serialization  %v", err)
	}

	return serialized

}
